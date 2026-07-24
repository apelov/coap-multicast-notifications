#!/bin/bash

C_DIR="/Users/apelov/Code/CoAP"
JAVA_DIR="/tmp/californium-thesis-work"
PCAP_FILE="$C_DIR/c_server_interop.pcap"

echo "=================================================="
echo "    C Server + 1 C Client + 1 Java Client"
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
rm -f /tmp/c_client_interop.log
rm -f /tmp/java_client_interop.log

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

    # Print diagnostics for C Client
    echo "--------------------------------------------------"
    echo "C Client logs (bound to 127.0.0.2):"
    tail -n 15 /tmp/c_client_interop.log 2>/dev/null
    echo "--------------------------------------------------"
    echo "Java Client logs:"
    tail -n 25 /tmp/java_client_interop.log 2>/dev/null
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

# 2. Compile C binaries if missing
cd "$C_DIR"
if [ ! -f "coap_server" ] || [ ! -f "coap_client" ]; then
    echo "Compiling C binaries..."
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

# 4. Start C Server
echo "Starting C Server..."
./coap_server -r mult >/tmp/c_server_interop.log 2>&1 &
SERVER_PID=$!
PIDS+=($SERVER_PID)

sleep 2

# 5. Start C Client bound to 127.0.0.2:56830
echo "Starting C Client (bound to 127.0.0.2)..."
./coap_client -h 127.0.0.1 -p 5683 -r mult -b "127.0.0.2" >/tmp/c_client_interop.log 2>&1 &
C_CLIENT_PID=$!
PIDS+=($C_CLIENT_PID)

# 6. Start Java Client (using AClient entrypoint)
echo "Starting Java Client..."
cd "$JAVA_DIR"
mvn exec:java -pl demo-apps/cf-helloworld-client \
  -Dexec.mainClass="org.eclipse.californium.examples.AClient" \
  -Dexec.args="mult 127.0.0.1 5683" >/tmp/java_client_interop.log 2>&1 &
JAVA_CLIENT_PID=$!
PIDS+=($JAVA_CLIENT_PID)

echo "--------------------------------------------------"
echo "All processes started. Capturing for 60 seconds..."
echo "--------------------------------------------------"

# 7. Wait 60 seconds with updates
for sec in {30,60}; do
    sleep 30
    echo "Progress: $sec seconds / 60 seconds elapsed..."
done

# 8. Shutdown and print results
cleanup
