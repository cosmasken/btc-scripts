extern crate balance;
use balance::WalletState;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum SpendError {
    MissingCodeCantRun,
    InsufficientFunds(String),
}

#[derive(Clone)]
pub struct Utxo {
    pub script_pubkey: Vec<u8>,
    pub amount: u64,
}

pub struct Outpoint {
    txid: [u8; 32],
    index: u32,
}

fn create_multisig_script(keys: Vec<Vec<u8>>) -> Vec<u8> {
    if keys.len() < 2 {
        panic!("Not enough keys to create multisig script");
    }

    let mut script = Vec::new();

    script.push(0x52); // OP_2

    for key in &keys[0..2] {
        script.push(key.len() as u8);
        script.extend(key);
    }

    script.push(0x52); // OP_2
    script.push(0xAE); // OP_CHECKMULTISIG

    script
}

fn get_p2wsh_program(script: &[u8], version: Option<u32>) -> Vec<u8> {
    let mut program = Vec::new();
    let redeem_script_hash = Sha256::digest(&script);

    assert_eq!(redeem_script_hash.len(), 32, "Invalid hash length");

    match version {
        Some(v) => {
            program.push(v as u8);
        }
        None => {
            program.push(0x00);
        }
    }
    program.push(0x20);
    program.extend(redeem_script_hash);

    program
}

fn input_from_utxo(txid: &[u8], index: u32) -> Vec<u8> {
    let mut input = Vec::new();

    input.extend(txid);

    input.extend(index.to_le_bytes());

    input.push(0x00); 

    input.extend((0xFFFFFFFFu32).to_le_bytes());

    input
}

fn output_from_options(script: &[u8], amount: u64) -> Vec<u8> {
    let mut output = Vec::new();

    output.extend(&amount.to_le_bytes());


    output.push(script.len() as u8);

    output.extend_from_slice(script);

    output
}

fn get_p2wpkh_scriptcode(utxo: &Utxo) -> Vec<u8> {
    let mut pubkey_hash = [0u8; 20];
    let script = &utxo.script_pubkey;

    if script.len() == 22 && script.starts_with(&[0x00, 0x14]) {
        pubkey_hash.copy_from_slice(&script[2..22]);
    }

    //construct the scriptcode
    let mut script_code = Vec::with_capacity(25);

    script_code.push(0x76); //OP_DUP
    script_code.push(0xa9); //OP_HASH160
    script_code.push(0x14); //length of pubkey hash 20bytes
    script_code.extend_from_slice(&pubkey_hash); //public key hash
    script_code.push(0x88); //OP_EQUALVERIFY
    script_code.push(0xac); //OP_CHECKSIG

    script_code
}

fn get_commitment_hash(
    outpoint: Outpoint,
    scriptcode: &[u8],
    value: u64,
    outputs: Vec<Utxo>,
) -> Vec<u8> {
    let mut data = Vec::new();

    // Version
    data.extend(&2u32.to_le_bytes());

    // All TX input outpoints (only one in our case)
    let mut outpoints = Vec::new();
    outpoints.extend_from_slice(&outpoint.txid);
    outpoints.extend(&outpoint.index.to_le_bytes());
    data.extend(&double_sha256(&outpoints));

    // All TX input sequences (only one for us, always default value)
    let sequence = 0xffffffffu32;
    data.extend(&double_sha256(&sequence.to_le_bytes()));

    // Single outpoint being spent
    data.extend_from_slice(&outpoint.txid);
    data.extend(&outpoint.index.to_le_bytes());

    // Scriptcode (the scriptPubKey in/implied by the output being spent, see BIP 143)
    data.push(scriptcode.len() as u8);
    data.extend_from_slice(scriptcode);

    // Value of output being spent
    data.extend(&(value as u64).to_le_bytes());

    // Sequence of output being spent (always default for us)
    data.extend(&sequence.to_le_bytes());

    // All TX outputs
    let mut outputs_info = Vec::new();
    for output in outputs {
        outputs_info.extend(&output.amount.to_le_bytes());
        outputs_info.push(output.script_pubkey.len() as u8);
        outputs_info.extend_from_slice(&output.script_pubkey);
    }
    data.extend(&double_sha256(&outputs_info));

    // Locktime (always default for us)
    let locktime = 0u32;
    data.extend(&locktime.to_le_bytes());

    // SIGHASH_ALL (always default for us)
    data.extend(&1u32.to_le_bytes());

    double_sha256(&data)
}
// this function helps in performing SHA256 double hashing
fn double_sha256(data: &[u8]) -> Vec<u8> {
    let first_hash = Sha256::digest(data);
    Sha256::digest(&first_hash).to_vec()
}

fn get_key_index(utxo: &Utxo, programs: Vec<&str>) -> u32 {
    if utxo.script_pubkey.len() != 22 || !utxo.script_pubkey.starts_with(&[0x00, 0x14]) {
        panic!("invalid script pubkey format")
    }

    let pubkey_hash = hex::encode(&utxo.script_pubkey);

    for (idx, program) in programs.iter().enumerate() {
        if pubkey_hash == *program {
            return idx as u32;
        }
    }

    panic!("key not found for utxo and the witness program")
}

fn sign(privkey: &[u8; 32], msg: Vec<u8>) -> Vec<u8> {

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(privkey).unwrap();
    let message = Message::from_digest_slice(&msg).unwrap();
    let mut signature = secp.sign_ecdsa(&message, &secret_key);

    //to keep the s value as low as possible, we normalize the signature
    signature.normalize_s();
    let mut der_signature = signature.serialize_der().as_ref().to_vec();
    der_signature.push(0x01); // SIGHASH_ALL

    der_signature
}

fn get_p2wpkh_witness(privkey: &[u8; 32], msg: Vec<u8>) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(privkey).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let compressed_pubkey = public_key.serialize();

    let signature = sign(privkey, msg);

    // Witness stack: [signature, compressed_pubkey]
    let mut witness = Vec::new();
    witness.push(signature);
    witness.push(compressed_pubkey.to_vec());

    // Serialize the witness stack
    let mut serialized_witness = Vec::new();
    serialized_witness.push(witness.len() as u8); // Number of stack items
    for item in witness {
        serialized_witness.push(item.len() as u8); // Length of each item
        serialized_witness.extend(item); // The item itself
    }

    serialized_witness
}

fn get_p2wsh_witness(privs: Vec<&[u8; 32]>, msg: Vec<u8>, redeem_script: &[u8]) -> Vec<u8> {
    let mut witness = Vec::new();
    witness.push(0);
    witness.push(0x00);
    let mut witness_count = 1;

    for privkey in privs {
        let der_signature = sign(privkey, msg.clone());
        witness.push(der_signature.len() as u8);
        witness.extend(&der_signature);
        witness_count += 1;
    }

    witness.push(redeem_script.len() as u8);
    witness.extend_from_slice(redeem_script);
    witness_count += 1;

    witness[0] = witness_count as u8;
    witness
}

// Given arrays of inputs, outputs, and witnesses, assemble the complete
// transaction and serialize it for broadcast. Return bytes as hex-encoded string
// suitable to broadcast with Bitcoin Core RPC.
// https://en.bitcoin.it/wiki/Protocol_documentation#tx
fn assemble_transaction(
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    witnesses: Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut transaction = Vec::new();

    // Debug each component

    transaction.extend(&2u32.to_le_bytes()); // 4 bytes

    transaction.push(0x00); // 1 byte
    transaction.push(0x01); // 1 byte

    transaction.push(inputs.len() as u8); // 1 byte

    for input in &inputs {
        transaction.extend(input);
    }

    transaction.push(outputs.len() as u8);

    for output in &outputs {
        transaction.extend(output);
    }

    for witness in &witnesses {
        transaction.extend(witness);
    }

    transaction.extend_from_slice(&0u32.to_le_bytes());

    transaction
}

fn get_txid(inputs: Vec<Vec<u8>>, outputs: Vec<Vec<u8>>) -> [u8; 32] {
    let mut transaction = Vec::new();
    transaction.extend(&2u32.to_le_bytes());
    transaction.push(inputs.len() as u8);

    for input in inputs {
        transaction.extend(&input);
    }
    transaction.push(outputs.len() as u8);
    for output in outputs {
        transaction.extend_from_slice(&output);
    }
    transaction.extend(&0u32.to_le_bytes());
    let hash = double_sha256(&transaction);
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&hash);
    txid.reverse();
    txid
}

pub fn spend_p2wpkh(wallet_state: &WalletState) -> Result<([u8; 32], String), SpendError> {
    const FEE: u64 = 1000; // Fixed fee for the transaction
    const AMT: u64 = 1000000; // Amount to send to the multisig output
    let required_amount = AMT + FEE; // Total amount needed (AMT + fee)

    // Choose an unspent coin worth more than the required amount
    let utxo = wallet_state
        .utxos
        .iter()
        .find(|&(_, &(_, amount))| (amount * 100_000_000.0) as u64 > required_amount)
        .ok_or(SpendError::InsufficientFunds(
            "Insufficient funds".to_string(),
        ))?;

    let ((txid, vout_index), (script_pubkey, amount)) = utxo;

    // Reverse the TXID hash so it's little-endian
    let txid_bytes = hex::decode(&txid).unwrap();
    let reversed_txid: Vec<u8> = txid_bytes.iter().rev().cloned().collect();

    // Convert the UTXO amount to satoshis
    let utxo_amount_sats = (amount * 100_000_000.0) as u64;
    let change_amount_sats = utxo_amount_sats - required_amount;
    let vout_index = *vout_index;

    // Create the transaction input from the UTXO
    let transaction_input = input_from_utxo(&reversed_txid, vout_index);

    // Create the 2-of-2 multisig script using the first two public keys
    let multisig_redeem_script = create_multisig_script(wallet_state.public_keys.clone());

    // Compute the P2WSH witness program from the multisig script
    let multisig_witness_program = get_p2wsh_program(&multisig_redeem_script, Some(0));

    // Create the multisig output (sending AMT to the multisig address)
    let multisig_output = output_from_options(&multisig_witness_program, AMT);
    // println!("Multisig Output: {:?}", hex::encode(&multisig_output));

    // Create a UTXO object for the input being spent
    let input_utxo = Utxo {
        script_pubkey: script_pubkey.clone(),
        amount: utxo_amount_sats,
    };

    // Compute the scriptcode for the input UTXO (required for signing)
    let input_scriptcode = get_p2wpkh_scriptcode(&input_utxo);
    // println!("Input ScriptCode: {:?}", hex::encode(&input_scriptcode));

    // Create the change output (sending change back to the 0th key's P2WPKH address)
    let change_output = output_from_options(&wallet_state.witness_programs[0], change_amount_sats);
    // println!("Change Output: {:?}", hex::encode(&change_output));

    // Create the outpoint for the input being spent
    let outpoint = Outpoint {
        txid: reversed_txid.try_into().unwrap(),
        index: vout_index,
    };

    // Define the outputs for the transaction
    let transaction_outputs = vec![
        Utxo {
            script_pubkey: multisig_witness_program.clone(),
            amount: AMT,
        },
        Utxo {
            script_pubkey: wallet_state.witness_programs[0].clone(),
            amount: change_amount_sats,
        },
    ];

    // Compute the commitment hash (digest to sign) for the input
    let commitment_hash = get_commitment_hash(
        outpoint,
        &input_scriptcode,
        utxo_amount_sats,
        transaction_outputs,
    );
    // println!("Commitment Hash: {:?}", hex::encode(&commitment_hash));

    // Fetch the private key needed to sign the input
    let witness_programs: Vec<String> = wallet_state
        .witness_programs
        .iter()
        .map(|x| hex::encode(x))
        .collect();
    let witness_programs: Vec<&str> = witness_programs.iter().map(|s| s.as_str()).collect();

    let key_index = get_key_index(&input_utxo, witness_programs.clone());
    // println!("Key Index: {:?}", key_index);

    let private_key: [u8; 32] = wallet_state
        .private_keys
        .get(key_index as usize)
        .ok_or(SpendError::MissingCodeCantRun)?
        .as_slice()[..32]
        .try_into()
        .unwrap();

    // println!("Private Key: {:?}", hex::encode(&private_key));

    // Sign the transaction input
    let witness = get_p2wpkh_witness(&private_key, commitment_hash);

    // Assemble the transaction
    let transaction_inputs = vec![transaction_input.clone()];
    let transaction_outputs = vec![multisig_output.clone(), change_output.clone()];
    let transaction_witnesses = vec![witness.clone()];

    // Serialize the transaction and compute the TXID
    let transaction = assemble_transaction(
        transaction_inputs.clone(),
        transaction_outputs.clone(),
        transaction_witnesses,
    );

    // Compute the TXID (hash of the transaction without witness data)
    let txid = get_txid(transaction_inputs, transaction_outputs);

    // println!("Transaction ID (hex): {}", hex::encode(&txid));

    // Return the TXID and the hex-encoded transaction
    Ok((txid, hex::encode(transaction)))
}

// Spend a 2-of-2 multisig p2wsh utxo and return the transaction
pub fn spend_p2wsh(wallet_state: &WalletState, txid: [u8; 32]) -> Result<Vec<Vec<u8>>, SpendError> {
    const FEE: u64 = 1000;
    const AMT: u64 = 1000000;

    let vout_index = 0; //index of the ouput AMT was sent

    // Reverse the txid hash so it's little-endian
    let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();

    let transaction_input = input_from_utxo(&reversed_txid, vout_index);

    let pubkey1 = wallet_state.public_keys[0].clone();
    let pubkey2 = wallet_state.public_keys[1].clone();

    let multisig_redeem_script = create_multisig_script(vec![pubkey1, pubkey2]);
    // let multisig_witness_program = get_p2wsh_program(&multisig_redeem_script, Some(0));;

    // Compute destination output script and output
    // Create the OP_RETURN output with your name (or nym) in ASCII
    let name = "Cosmas Aruba Ken"; // Replace with your name or nym
    let mut op_return_script = vec![
        0x6a,             // OP_RETURN
        name.len() as u8, // Pushdata length
    ];
    op_return_script.extend_from_slice(name.as_bytes());
    let op_return_output = output_from_options(&op_return_script, 0);

    // Compute change output script and output
    let change_amount = AMT - FEE;
    let change_output = output_from_options(&wallet_state.witness_programs[0], change_amount);

    // Get the message to sign
    // 1.create an outpoint
    let outpoint = Outpoint {
        txid: reversed_txid.try_into().unwrap(),
        index: vout_index,
    };
    // 2.define the outputs for the transaction
    let transaction_outputs = vec![
        //output from p2wsh; input to the p2wpkh
        Utxo {
            script_pubkey: op_return_script.clone(),
            amount: 0,
        },
        //change into the sender
        Utxo {
            script_pubkey: wallet_state.witness_programs[0].clone(),
            amount: change_amount,
        },
    ];

    // Sign!
    let commitment_hash = get_commitment_hash(
        outpoint,
        &multisig_redeem_script, //scriptcode for p2wsh is the redeem script,
        AMT,
        transaction_outputs,
    );

    // Fetch the private keys needed to sign the input
    let privkey1: [u8; 32] = wallet_state.private_keys[0]
        .clone()
        .try_into()
        .expect("private key length is not 32 bytes");
    let privkey2: [u8; 32] = wallet_state.private_keys[1]
        .clone()
        .try_into()
        .expect("private key length is not 32 bytes");

    // Sign the transaction input
    let witness = get_p2wsh_witness(
        vec![&privkey1, &privkey2],
        commitment_hash,
        &multisig_redeem_script,
    );

    // Assemble
    let transaction_inputs = vec![transaction_input.clone()];
    let transaction_outputs = vec![op_return_output.clone(), change_output.clone()];
    let transaction_witnesses = vec![witness.clone()];

    let transaction = assemble_transaction(
        transaction_inputs.clone(),
        transaction_outputs.clone(),
        transaction_witnesses,
    );

    // For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    // return txid final-tx
    let txid2 = get_txid(transaction_inputs, transaction_outputs);

    // println!("Transaction ID (hex): {}", hex::encode(&txid));

    // Return the TXID and the hex-encoded transaction
    Ok(vec![txid2.to_vec(), transaction])
}
