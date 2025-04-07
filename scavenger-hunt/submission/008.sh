# Which public key signed input 0 in this tx:
#   `e5969add849689854ac7f28e45628b89f7454b83e9699e551ce14b6f90c86163`
RAWTX=$(bitcoin-cli getrawtransaction e5969add849689854ac7f28e45628b89f7454b83e9699e551ce14b6f90c86163 1)
ENCODED=$(echo $RAWTX | jq -r '.vin[0].txinwitness[2]')
DECODED=$(bitcoin-cli decodescript $ENCODED)
echo $DECODED | jq -r '.asm' | cut -d ' ' -f2