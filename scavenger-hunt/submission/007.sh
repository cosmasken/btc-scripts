# Only one single output remains unspent from block 123,321. What address was it sent to?
HASH=$(bitcoin-cli getblockhash "123321")
BLOCKDATA=$(bitcoin-cli getblock $HASH)
INPUTTX=$(echo $BLOCKDATA | jq -r '.tx[6]')
ADDR=$(bitcoin-cli getrawtransaction "$INPUTTX" 1)
echo $ADDR | jq -r '.vout[0].scriptPubKey.address'