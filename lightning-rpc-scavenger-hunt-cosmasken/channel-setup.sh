#!/bin/bash
command_output=$(lncli -n signet getinfo)

# Extracting the pubkey using jq
pubkey=$(echo "$command_output" | jq -r ".identity_pubkey")

# Open channel
lncli -n signet --lnddir=.lnd1 --rpcserver=localhost:10008 openchannel --node_key="$pubkey"  --local_amt=100000000 --connect=localhost:9735
