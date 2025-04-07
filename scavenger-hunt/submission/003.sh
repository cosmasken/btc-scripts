# How many new outputs were created by block 123,456?
HASH=$(bitcoin-cli getblockhash 123456)
BLOCK=$(bitcoin-cli getblock $HASH 2)

NEW_OUTPUTS=$(echo $BLOCK | jq '
  .tx as $transactions |
  [ 
    $transactions[] | 
    .vout | length
  ] | add
')

echo $NEW_OUTPUTS