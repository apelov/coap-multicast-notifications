#!/bin/bash

# Default parameters
USE_OSCORE=""
NUM_CLIENTS=0

# Print usage
print_usage() {
    echo "Usage: $0 [-s] <number_of_clients>"
    echo "  -s : Enable OSCORE protection"
    exit 1
}

# Parse options
while getopts "s" opt; do
    case "$opt" in
        s)
            USE_OSCORE="-s"
            ;;
        *)
            print_usage
            ;;
    esac
done
shift $((OPTIND-1))

# Check arguments
if [ $# -ne 1 ]; then
    print_usage
fi

NUM_CLIENTS=$1

# Validate number of clients
if ! [[ "$NUM_CLIENTS" =~ ^[0-9]+$ ]] || [ "$NUM_CLIENTS" -le 0 ]; then
    echo "Error: Number of clients must be a positive integer."
    print_usage
fi

# Array to keep track of background PIDs
PIDS=()

# Cleanup function to kill all background processes on exit
cleanup() {
    echo -e "\nStopping all processes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done
    exit 0
}

# Set trap for SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

echo "=================================================="
echo "Starting CoAP Multicast Observe Demo"
echo "  Clients: $NUM_CLIENTS"
echo "  OSCORE:  $( [ -n "$USE_OSCORE" ] && echo "Enabled" || echo "Disabled" )"
echo "=================================================="

# 1. Compile binaries if needed
if [ ! -f ./coap_server ] || [ ! -f ./coap_client ]; then
    echo "Compiling binaries..."
    make vienna || exit 1
fi

# 2. Start the server in the background
echo "Starting CoAP server..."
./coap_server $USE_OSCORE &
SERVER_PID=$!
PIDS+=($SERVER_PID)

# Give the server a second to bind to the port
sleep 1

# 3. Start the clients in the background
for ((i=1; i<=NUM_CLIENTS; i++)); do
    echo "Starting Client $i..."
    # Run client, prefixing its stdout/stderr with [Client X]
    ./coap_client $USE_OSCORE 2>&1 | sed "s/^/[Client $i] /" &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    # Slight stagger to prevent simultaneous socket binding race condition
    sleep 0.1
done

echo "--------------------------------------------------"
echo "All processes started. Press Ctrl+C to stop."
echo "--------------------------------------------------"

# Wait for background processes to keep script running
wait
