# Create a 1-of-4 P2SH multisig address from the public keys in the four inputs of this tx:
#   `37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517`

TX_DATA=$(bitcoin-cli getrawtransaction 37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517 1)
NPUB1=$(echo "$TX_DATA" | jq -r '.vin[0].txinwitness[1]')
NPUB2=$(echo "$TX_DATA" | jq -r '.vin[1].txinwitness[1]')
NPUB3=$(echo "$TX_DATA" | jq -r '.vin[2].txinwitness[1]')
NPUB4=$(echo "$TX_DATA" | jq -r '.vin[3].txinwitness[1]')
MULTISIGADDR=$(bitcoin-cli createmultisig 1 "[\"$NPUB1\",\"$NPUB2\",\"$NPUB3\",\"$NPUB4\"]" )
echo $MULTISIGADDR | jq -r '.address'