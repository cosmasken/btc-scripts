# How many satoshis did this transaction pay for fee?:
#  `c346d9277128f5d67740f8847f11aff5cef440b6d102fcd5ddcdb40d9a12df42`

TXID="c346d9277128f5d67740f8847f11aff5cef440b6d102fcd5ddcdb40d9a12df42"

TX_DETAILS=$(bitcoin-cli getrawtransaction "$TXID" 1)

TOTAL_INPUTS=0
for vin in $(echo "$TX_DETAILS" | jq -r '.vin[].txid'); do
  vout=$(echo "$TX_DETAILS" | jq -r --arg txid "$vin" '.vin[] | select(.txid == $txid) | .vout')
  referenced_tx=$(bitcoin-cli getrawtransaction "$vin" 1)
  amount=$(echo "$referenced_tx" | jq -r --argjson vout "$vout" '.vout[$vout].value')
  satoshis=$(echo "$amount * 100000000 / 1" | bc)
  TOTAL_INPUTS=$(echo "$TOTAL_INPUTS + $satoshis" | bc)
done

TOTAL_OUTPUTS=$(echo "$TX_DETAILS" | jq -r '[.vout[].value] | add')
TOTAL_OUTPUTS=$(echo "$TOTAL_OUTPUTS * 100000000 / 1" | bc) # Convert to satoshis

FEE=$(echo "$TOTAL_INPUTS - $TOTAL_OUTPUTS" | bc)

echo $FEE