#!/bin/bash

C_DIR="/Users/apelov/Code/CoAP"
JAVA_DIR="/tmp/californium-thesis-work"
PCAP_FILE="$C_DIR/java_server_3c.pcap"

echo "=================================================="
echo "    Java Server + 3 C Clients (Loopback Aliases)"
echo "=================================================="

# Detect OS and interfaces
OS_NAME=$(uname -s)
if [ "$OS_NAME" = "Darwin" ]; then
    LOOPBACK_INTF="lo0"
    PHYS_INTF="en0"
    PHYS_IP=$(ipconfig getifaddr en0)
else
    LOOPBACK_INTF="lo"
    PHYS_INTF=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -n1)
    if [ -z "$PHYS_INTF" ]; then
        PHYS_INTF="eth0"
    fi
    PHYS_IP=$(ip -4 addr show dev "$PHYS_INTF" 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 | head -n1)
fi

if [ -z "$PHYS_IP" ]; then
    echo "Warning: Physical IP not found. Falling back to 127.0.0.1"
    PHYS_IP="127.0.0.1"
fi

echo "OS: $OS_NAME"
echo "Loopback interface: $LOOPBACK_INTF"
echo "Physical interface: $PHYS_INTF ($PHYS_IP)"

# 1. Clean Port Contention
echo "Checking and clearing ports 5683 and 56830..."
PORT_PIDS=$(lsof -t -i :5683 -i :56830 2>/dev/null)
if [ -n "$PORT_PIDS" ]; then
    echo "Killing processes using ports 5683/56830 (PIDs: $PORT_PIDS)..."
    kill -9 $PORT_PIDS 2>/dev/null
    sleep 1
fi

# Remove existing PCAP and temp logs
rm -f "$PCAP_FILE"
rm -f "$C_DIR/lo_jh.pcap" "$C_DIR/phys_jh.pcap"
rm -f /tmp/c_client_alias_*.log

PIDS=()
TCPDUMP_PIDS=()

cleanup() {
    echo -e "\nStopping all background client/server processes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done

    echo "Stopping packet captures..."
    for pid in "${TCPDUMP_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done

    sleep 2

    # Merge captured pcaps if they exist
    cd "$C_DIR"
    if [ -f lo_jh.pcap ] && [ -f phys_jh.pcap ]; then
        echo "Merging loopback and physical packet captures..."
        MERGECAP_BIN="mergecap"
        if [ ! -x "$(command -v mergecap)" ]; then
            if [ -f "/Applications/Wireshark.app/Contents/MacOS/mergecap" ]; then
                MERGECAP_BIN="/Applications/Wireshark.app/Contents/MacOS/mergecap"
            fi
        fi
        "$MERGECAP_BIN" -w "$PCAP_FILE" lo_jh.pcap phys_jh.pcap 2>/dev/null
        rm -f lo_jh.pcap phys_jh.pcap
    elif [ -f lo_jh.pcap ]; then
        mv lo_jh.pcap "$PCAP_FILE"
    elif [ -f phys_jh.pcap ]; then
        mv phys_jh.pcap "$PCAP_FILE"
    fi

    # Print diagnostics for C Clients
    echo "--------------------------------------------------"
    echo "C Client 1 logs (bound to 127.0.0.1):"
    tail -n 12 /tmp/c_client_alias_1.log 2>/dev/null
    echo "--------------------------------------------------"
    echo "C Client 2 logs (bound to 127.0.0.2):"
    tail -n 12 /tmp/c_client_alias_2.log 2>/dev/null
    echo "--------------------------------------------------"
    echo "C Client 3 logs (bound to 127.0.0.3):"
    tail -n 12 /tmp/c_client_alias_3.log 2>/dev/null
    echo "--------------------------------------------------"

    if [ -f "$PCAP_FILE" ]; then
        echo "=================================================="
        echo "PCAP file successfully generated: $PCAP_FILE"
        echo "Captured packets summary:"
        echo "--------------------------------------------------"
        tcpdump -r "$PCAP_FILE" -n 2>/dev/null | wc -l | xargs echo "Total Packets Captured: "
        echo "--------------------------------------------------"
        echo "Open the PCAP in Wireshark with: open $PCAP_FILE"
        echo "=================================================="
    fi

    exit 0
}

# Trap Ctrl+C (SIGINT) and SIGTERM
trap cleanup SIGINT SIGTERM

# 2. Compile client if missing
cd "$C_DIR"
if [ ! -f "coap_client" ]; then
    echo "Compiling client..."
    make || exit 1
fi

# 3. Start Packet Capture on loopback and physical interfaces
echo "Starting packet captures..."
tcpdump -i "$LOOPBACK_INTF" -w "$C_DIR/lo_jh.pcap" -U "udp port 5683 or udp port 56830" 2>/dev/null &
LO_PID=$!
TCPDUMP_PIDS+=($LO_PID)

tcpdump -i "$PHYS_INTF" -w "$C_DIR/phys_jh.pcap" -U "udp port 5683 or udp port 56830" 2>/dev/null &
EN_PID=$!
TCPDUMP_PIDS+=($EN_PID)

sleep 2

# 4. Start Java Server
echo "Starting Java Server..."
cd "$JAVA_DIR"
mvn exec:java -pl demo-apps/cf-helloworld-server \
  -Dexec.mainClass="org.eclipse.californium.examples.AHelloWorldServer" >/tmp/java_server_hook.log 2>&1 &
SERVER_PID=$!
PIDS+=($SERVER_PID)

# Give Java server time to fully compile and bind (15 seconds)
echo "Waiting for Java Server to initialize (15 seconds)..."
sleep 15

# 5. Start 3 C Clients bound to loopback IP aliases (127.0.0.1, 127.0.0.2, 127.0.0.3)
cd "$C_DIR"
for i in {1..3}; do
    BIND_IP="127.0.0.$i"
    echo "Starting C Client $i (bound to $BIND_IP)..."
    ./coap_client -h 127.0.0.1 -p 5683 -r mult -b "$BIND_IP" >/tmp/c_client_alias_${i}.log 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    sleep 0.5
done

echo "--------------------------------------------------"
echo "All processes started. Capturing for 60 seconds..."
echo "--------------------------------------------------"

# 6. Wait 60 seconds with updates
for sec in {30,60}; do
    sleep 30
    echo "Progress: $sec seconds / 60 seconds elapsed..."
done

# 7. Shutdown and print results
cleanup
