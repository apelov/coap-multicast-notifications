#!/bin/bash

C_DIR="/Users/apelov/Code/CoAP"
PCAP_FILE="$C_DIR/demo.pcap"

echo "=================================================="
echo "    CoAP Multicast Observe PCAP Capture Demo"
echo "=================================================="

# 1. Compile if needed
if [ ! -f "$C_DIR/coap_server" ] || [ ! -f "$C_DIR/coap_client" ]; then
    echo "Compiling binaries..."
    cd "$C_DIR" && make || exit 1
fi

# Clean up any existing pcap
rm -f "$PCAP_FILE"

# 2. Start tcpdump in the background
echo "Starting tcpdump on lo0..."
# -U makes tcpdump write packets immediately to the file rather than buffering
tcpdump -i lo0 -w "$PCAP_FILE" -U "udp port 5683 or udp port 56830" 2>/dev/null &
TCPDUMP_PID=$!

sleep 1.5

# 3. Start C Server
echo "Starting C Server..."
./coap_server >/dev/null 2>&1 &
SERVER_PID=$!

sleep 1

# 4. Start C Client
echo "Starting C Client..."
./coap_client >/dev/null 2>&1 &
CLIENT_PID=$!

echo "Capturing traffic for 12 seconds..."
sleep 12

# 5. Stop all background processes
echo "Stopping server, client, and tcpdump..."
kill "$CLIENT_PID" 2>/dev/null
kill "$SERVER_PID" 2>/dev/null
kill "$TCPDUMP_PID" 2>/dev/null

sleep 1.5

# 6. Verify and read PCAP file
if [ -f "$PCAP_FILE" ]; then
    echo "=================================================="
    echo "Successfully captured packets in: $PCAP_FILE"
    echo "=================================================="
    echo "Summary of captured UDP packets:"
    echo "--------------------------------------------------"
    tcpdump -r "$PCAP_FILE" -n
    echo "--------------------------------------------------"
    echo "You can open '$PCAP_FILE' directly in Wireshark!"
else
    echo "Error: Failed to generate pcap file."
fi
