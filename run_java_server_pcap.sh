#!/bin/bash

C_DIR="/Users/apelov/Code/CoAP"
JAVA_DIR="/tmp/californium-thesis-work"
PCAP_FILE="$C_DIR/interop_demo.pcap"

echo "=================================================="
echo "   Mixed Java/C Interop Capture (5 Minute Run)"
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
rm -f "$C_DIR/lo0.pcap" "$C_DIR/en0.pcap"
rm -f /tmp/c_client_*.log /tmp/java_client_*.log

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
    if [ -f lo0.pcap ] && [ -f en0.pcap ]; then
        echo "Merging lo0 and en0 packet captures into $PCAP_FILE..."
        /Applications/Wireshark.app/Contents/MacOS/mergecap -w "$PCAP_FILE" lo0.pcap en0.pcap 2>/dev/null
        rm -f lo0.pcap en0.pcap
    elif [ -f lo0.pcap ]; then
        mv lo0.pcap "$PCAP_FILE"
    elif [ -f en0.pcap ]; then
        mv en0.pcap "$PCAP_FILE"
    fi

    # Print log diagnostics
    echo "--------------------------------------------------"
    echo "C Client logs check:"
    tail -n 2 /tmp/c_client_*.log 2>/dev/null
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
if [ ! -f "$C_DIR/coap_server" ] || [ ! -f "$C_DIR/coap_client" ]; then
    echo "Compiling C binaries..."
    cd "$C_DIR" && make || exit 1
fi

# 3. Start Packet Capture on both lo0 (unicast) and en0 (multicast)
echo "Starting packet captures on lo0 and en0..."
tcpdump -i lo0 -w "$C_DIR/lo0.pcap" -U "udp port 5683 or udp port 56830" 2>/dev/null &
LO_PID=$!
TCPDUMP_PIDS+=($LO_PID)

tcpdump -i en0 -w "$C_DIR/en0.pcap" -U "udp port 5683 or udp port 56830" 2>/dev/null &
EN_PID=$!
TCPDUMP_PIDS+=($EN_PID)

sleep 2

# 4. Start Java Server
echo "Starting Java Server..."
cd "$JAVA_DIR"
mvn exec:java -pl demo-apps/cf-helloworld-server \
  -Dexec.mainClass="org.eclipse.californium.examples.AHelloWorldServer" >/tmp/java_server.log 2>&1 &
SERVER_PID=$!
PIDS+=($SERVER_PID)

# Give Java server time to fully compile and bind (15 seconds)
echo "Waiting for Java Server to initialize (15 seconds)..."
sleep 15

# 5. Start 3 C Clients (talking to /mult)
cd "$C_DIR"
for i in {1..3}; do
    echo "Starting C Client $i..."
    ./coap_client -h 127.0.0.1 -p 5683 -r mult >/tmp/c_client_${i}.log 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    sleep 0.2
done

# 6. Start 3 Java Clients (talking to /mult)
cd "$JAVA_DIR"
for i in {1..3}; do
    echo "Starting Java Client $i..."
    mvn exec:java -pl demo-apps/cf-helloworld-client \
      -Dexec.mainClass="org.eclipse.californium.examples.MulticastObserveClient" \
      -Dexec.args="coap://127.0.0.1:5683/mult" >/tmp/java_client_${i}.log 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    sleep 0.5
done

echo "--------------------------------------------------"
echo "All processes started. Capturing for 5 minutes..."
echo "--------------------------------------------------"

# 7. Wait 5 minutes with updates
for min in {1..10}; do
    sleep 30
    echo "Progress: $((min * 30)) seconds / 300 seconds elapsed..."
done

# 8. Shutdown and print results
cleanup
