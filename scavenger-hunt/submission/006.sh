# Which tx in block 257,343 spends the COINBASE output of block 256,128?
HASH_256128=$(bitcoin-cli getblockhash 256128)
HASH_257343=$(bitcoin-cli getblockhash 257343)
BLOCK_DATA_256128=$(bitcoin-cli getblock $HASH_256128)
BLOCK_DATA_257343=$(bitcoin-cli getblock $HASH_257343)
COINBASE256128=$(echo $BLOCK_DATA_256128 | jq -r '.tx[0]')
TX1=$(echo $BLOCK_DATA_257343 | jq -r '.tx[0]')
TX2=$(echo $BLOCK_DATA_257343 | jq -r '.tx[1]')
TX3=$(echo $BLOCK_DATA_257343 | jq -r '.tx[2]')
#find result
bitcoin-cli getrawtransaction "$TX1" 1 | grep $COINBASE256128
bitcoin-cli getrawtransaction "$TX2" 1 | grep $COINBASE256128
# result in tx3
echo "$TX3"
