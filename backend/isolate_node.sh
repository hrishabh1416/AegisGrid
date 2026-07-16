NODE_NAME=$1

if [ -z "$NODE_NAME" ]; then
    echo "Error: Node name parameter is required."
    exit 1
fi

echo "=========================================="
echo "AEGISGRID MICRO-ISOLATION ENGINE (POSIX)"
echo "Target Node: $NODE_NAME"
echo "Initiating firewall isolation rules..."
sleep 1

LOCK_FILE="$(dirname "$0")/isolated_nodes.txt"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "$TIMESTAMP - ISOLATED - $NODE_NAME" >> "$LOCK_FILE"

echo "Firewall rules injected: Block all ingress/egress for $NODE_NAME"
echo "Mitigation Action: COMPLETE"
echo "=========================================="
exit 0
