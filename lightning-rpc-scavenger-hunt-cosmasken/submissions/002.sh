#!/bin/bash
# Fill in lncli commands to lookup the base fee of the node below broadcast for the channel id provided.

node="03ebc7280ff486f94cee51cff45a0fc521e9fe2560c02563ab191552fa90d4017d"
channel_id="6102289534222336"

# This lncli command allows the script to run against signet nodes for testing purposes, refer to it using $lncli.
# You may comment it out and use your own testing node if you would like, but this line *must* be uncommented when you push to test.
wd=$(pwd)
lncli="lncli -n=signet --rpcserver=boss2025.xyz:10007 --tlscertpath="$wd"/test/lnd2-tls.cert --macaroonpath="$wd"/test/lnd2-readonly.macaroon "


chaninfo=$($lncli getchaninfo $channel_id)

# get correct node policy (node1_pub or node2_pub)
node1_pub=$(echo $chaninfo | jq -r '.node1_pub')
node2_pub=$(echo $chaninfo | jq -r '.node2_pub')
if [ "$node" == "$node1_pub" ]; then
	node_policy=$(echo $chaninfo | jq -r '.node1_policy')
else
	node_policy=$(echo $chaninfo | jq -r '.node2_policy')
fi

# get base fee
base_fee=$(echo $node_policy | jq -r '.fee_base_msat')
echo $base_fee