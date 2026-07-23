#!/bin/bash

# Directories
C_DIR="/Users/apelov/Code/CoAP"
JAVA_DIR="/tmp/californium-thesis-work"

# Default resource paths based on server
# Java server uses /mult by default. C server can use /obs by default.
RESOURCE=""

# PIDs to cleanup
PIDS=()

cleanup() {
    echo -e "\nStopping all background processes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done
    exit 0
}

# Trap Ctrl+C (SIGINT) and SIGTERM to clean up all background jobs
trap cleanup SIGINT SIGTERM

echo "=================================================="
echo "   CoAP Multicast Observe Interop Demo Manager"
echo "=================================================="

# 1. Select Server
echo "Select the server to run:"
echo "  [1] C Server"
echo "  [2] Java Server"
read -rp "Enter choice [1-2]: " SERVER_CHOICE

if [ "$SERVER_CHOICE" = "1" ]; then
    SERVER_TYPE="C"
    RESOURCE="obs"
elif [ "$SERVER_CHOICE" = "2" ]; then
    SERVER_TYPE="Java"
    RESOURCE="mult"
else
    echo "Invalid choice. Exiting."
    exit 1
fi

# 2. Configure Client Counts
read -rp "Enter number of C clients to run: " C_CLIENTS_COUNT
read -rp "Enter number of Java clients to run: " JAVA_CLIENTS_COUNT

# Validate counts
if ! [[ "$C_CLIENTS_COUNT" =~ ^[0-9]+$ ]] || ! [[ "$JAVA_CLIENTS_COUNT" =~ ^[0-9]+$ ]]; then
    echo "Error: Client counts must be non-negative integers."
    exit 1
fi

TOTAL_CLIENTS=$((C_CLIENTS_COUNT + JAVA_CLIENTS_COUNT))
if [ "$TOTAL_CLIENTS" -le 0 ]; then
    echo "Error: You must run at least 1 client."
    exit 1
fi

# 3. Verify Build Status
# C Build check
if [ "$SERVER_TYPE" = "C" ] || [ "$C_CLIENTS_COUNT" -gt 0 ]; then
    if [ ! -f "$C_DIR/coap_server" ] || [ ! -f "$C_DIR/coap_client" ]; then
        echo "C binaries missing. Compiling..."
        cd "$C_DIR" && make || exit 1
    fi
fi

# Java Build check
if [ "$SERVER_TYPE" = "Java" ] || [ "$JAVA_CLIENTS_COUNT" -gt 0 ]; then
    # Verify Java directory exists
    if [ ! -d "$JAVA_DIR" ]; then
        echo "Error: Java reference implementation directory not found at $JAVA_DIR."
        exit 1
    fi
    # Check if compiled target exists. If not, build it.
    if [ ! -d "$JAVA_DIR/californium-core/target" ]; then
        echo "Java project not compiled. Building with Maven (skipping tests)..."
        cd "$JAVA_DIR" && mvn clean install -DskipTests || exit 1
    fi
fi

echo "--------------------------------------------------"
echo "Starting Demo configuration:"
echo "  Server:   $SERVER_TYPE (Resource path: /$RESOURCE)"
echo "  Clients:  $C_CLIENTS_COUNT (C) + $JAVA_CLIENTS_COUNT (Java)"
echo "--------------------------------------------------"

# 4. Start the Server
if [ "$SERVER_TYPE" = "C" ]; then
    echo "Starting C Server..."
    cd "$C_DIR"
    ./coap_server -r "$RESOURCE" 2>&1 | sed "s/^/[Server-C] /" &
    SERVER_PID=$!
else
    echo "Starting Java Server..."
    cd "$JAVA_DIR"
    mvn exec:java -pl demo-apps/cf-helloworld-server \
      -Dexec.mainClass="org.eclipse.californium.examples.AHelloWorldServer" 2>&1 | sed "s/^/[Server-Java] /" &
    SERVER_PID=$!
fi
PIDS+=($SERVER_PID)

# Give the server 2 seconds to boot and start listening
sleep 2

# 5. Start C Clients
if [ "$C_CLIENTS_COUNT" -gt 0 ]; then
    cd "$C_DIR"
    for ((i=1; i<=C_CLIENTS_COUNT; i++)); do
        echo "Starting C Client $i (Resource: /$RESOURCE)..."
        ./coap_client -h 127.0.0.1 -p 5683 -r "$RESOURCE" 2>&1 | sed "s/^/[Client-C-$i] /" &
        CLIENT_PID=$!
        PIDS+=($CLIENT_PID)
        sleep 0.1
    done
fi

# 6. Start Java Clients
if [ "$JAVA_CLIENTS_COUNT" -gt 0 ]; then
    cd "$JAVA_DIR"
    for ((i=1; i<=JAVA_CLIENTS_COUNT; i++)); do
        echo "Starting Java Client $i (Resource: /$RESOURCE)..."
        mvn exec:java -pl demo-apps/cf-helloworld-client \
          -Dexec.mainClass="org.eclipse.californium.examples.MulticastObserveClient" \
          -Dexec.args="coap://127.0.0.1:5683/$RESOURCE" 2>&1 | sed "s/^/[Client-Java-$i] /" &
        CLIENT_PID=$!
        PIDS+=($CLIENT_PID)
        sleep 0.2
    done
fi

echo "--------------------------------------------------"
echo "All processes running. Press Ctrl+C to stop."
echo "--------------------------------------------------"

wait
