# Only one tx in block 444,431 signals opt-in RBF. What is its txid?
#!/bin/bash

BLOCK_HEIGHT=444431

BLOCK_HASH=$(bitcoin-cli getblockhash $BLOCK_HEIGHT)

BLOCK_DATA=$(bitcoin-cli getblock "$BLOCK_HASH" 2)

# Use jq to find all transactions that signal opt-in RBF (sequence < 4294967294)
RBF_TX_IDS=$(echo "$BLOCK_DATA" | jq -r '
  .tx[] | 
  select(.vin[]? | .sequence < 4294967294) | 
  .txid
')

# Check if any RBF transactions were found and output the result
if [ -n "$RBF_TX_IDS" ]; then
  echo "$RBF_TX_IDS"
else
  echo "No transaction in block $BLOCK_HEIGHT signals opt-in RBF."
fi