#!/bin/bash

C_DIR="/Users/apelov/Code/CoAP"
JAVA_DIR="/tmp/californium-thesis-work"
PCAP_FILE="$C_DIR/java_server_3c.pcap"

echo "=================================================="
echo "    Java Server + 3 C Clients (using Loopback IPs)"
echo "=================================================="

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
rm -f "$C_DIR/lo0_jh.pcap" "$C_DIR/en0_jh.pcap"
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
    if [ -f lo0_jh.pcap ] && [ -f en0_jh.pcap ]; then
        echo "Merging lo0 and en0 packet captures into $PCAP_FILE..."
        /Applications/Wireshark.app/Contents/MacOS/mergecap -w "$PCAP_FILE" lo0_jh.pcap en0_jh.pcap 2>/dev/null
        rm -f lo0_jh.pcap en0_jh.pcap
    elif [ -f lo0_jh.pcap ]; then
        mv lo0_jh.pcap "$PCAP_FILE"
    elif [ -f en0_jh.pcap ]; then
        mv en0_jh.pcap "$PCAP_FILE"
    fi

    # Print diagnostics for C Clients
    echo "--------------------------------------------------"
    echo "C Client 1 logs (bound to 127.0.0.1):"
    tail -n 5 /tmp/c_client_alias_1.log 2>/dev/null
    echo "--------------------------------------------------"
    echo "C Client 2 logs (bound to 127.0.0.2):"
    tail -n 5 /tmp/c_client_alias_2.log 2>/dev/null
    echo "--------------------------------------------------"
    echo "C Client 3 logs (bound to 127.0.0.3):"
    tail -n 5 /tmp/c_client_alias_3.log 2>/dev/null
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

# 3. Start Packet Capture on both lo0 (unicast) and en0 (multicast)
echo "Starting packet captures on lo0 and en0..."
tcpdump -i lo0 -w "$C_DIR/lo0_jh.pcap" -U "udp port 5683 or udp port 56830" 2>/dev/null &
LO_PID=$!
TCPDUMP_PIDS+=($LO_PID)

tcpdump -i en0 -w "$C_DIR/en0_jh.pcap" -U "udp port 5683 or udp port 56830" 2>/dev/null &
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

# 5. Start 3 C Clients on loopback IP aliases
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
echo "All processes started. Capturing for 2 minutes..."
echo "--------------------------------------------------"

# 6. Wait 2 minutes with updates
for sec in {30,60,90,120}; do
    sleep 30
    echo "Progress: $sec seconds / 120 seconds elapsed..."
done

# 7. Shutdown and print results
cleanup
