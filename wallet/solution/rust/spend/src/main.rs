extern crate balance;
use balance::{recover_wallet_state, EXTENDED_PRIVATE_KEY};
use spend::{spend_p2wpkh, spend_p2wsh};

fn main() {
    let wallet_state = match recover_wallet_state(EXTENDED_PRIVATE_KEY) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to recover wallet state: {:?}", e);
            return;
        }
    };
    let (txid1, tx1) = match spend_p2wpkh(&wallet_state) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Failed to spend from P2WPKH: {:?}", e);
            return;
        }
    };
    println!("{}", tx1);

    match spend_p2wsh(&wallet_state, txid1) {
        Ok(transaction_data) => {
            let tx2 = hex::encode(&transaction_data[1]);
            println!("{}", tx2);
        }
        Err(e) => {
            eprintln!("Failed to create the second transaction: {:?}", e);
        }
    }
}
