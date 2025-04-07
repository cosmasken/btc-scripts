use std::error::Error;
use std::fs::File;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::io::{self, BufRead, Write};

#[derive(Debug)]
struct PriorityQueueItem {
    fee: u64,
    weight: u64,
    txid: String,
}

impl Ord for PriorityQueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.fee * other.weight).cmp(&(self.weight * other.fee))
    }
}

impl PartialOrd for PriorityQueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PriorityQueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.fee * other.weight == other.fee * self.weight
    }
}

impl Eq for PriorityQueueItem {}

pub fn sort_transactions(transactions: &HashMap<String, Transaction>) -> Vec<String> {
    let mut in_degree: HashMap<&String, usize> = transactions
        .iter()
        .map(|(txid, tx)| {
            let count = tx
                .parents
                .iter()
                .filter(|p| transactions.contains_key(*p))
                .count();
            (txid, count)
        })
        .collect();

    let mut priority_queue = BinaryHeap::new();
    for (txid, tx) in transactions.iter() {
        if in_degree[txid] == 0 {
            priority_queue.push(PriorityQueueItem {
                fee: tx.fee,
                weight: tx.weight,
                txid: txid.clone(),
            })
        }
    }

    let mut sorted_transactions = Vec::new();
    while let Some(item) = priority_queue.pop() {
        let txid = item.txid;
        sorted_transactions.push(txid.clone());

        if let Some(tx) = transactions.get(&txid) {
            for child in &tx.children {
                if let Some(degree) = in_degree.get_mut(child) {
                    *degree -= 1;
                    if *degree == 0 {
                        let child_tx = &transactions.get(child).unwrap();
                        priority_queue.push(PriorityQueueItem {
                            fee: child_tx.fee,
                            weight: child_tx.weight,
                            txid: child.clone(),
                        })
                    }
                }
            }
        }
    }

    sorted_transactions
}

pub fn save_block_to_file(
    block: Vec<String>,
    transactions: &HashMap<String, Transaction>,
    output_path: &str,
) -> io::Result<()> {
    let mut file = File::create(output_path)?;

    let mut total_weight = 0;

    for txid in &block {
        if let Some(tx) = transactions.get(txid) {
            total_weight += tx.weight;
            writeln!(file, "{}", txid)?;
        }
    }

    if total_weight > 4_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Block weight exceeds maximum limit of 4,000,000",
        ));
    }

    Ok(())
}

pub fn has_duplicate_transactions(block_transactions: Vec<String>) -> bool {
    let mut seen_transactions = HashSet::new();

    for tx in block_transactions {
        if !seen_transactions.insert(tx) {
            println!("length of seen_transaction {}", seen_transactions.len());
            return false;
        }
    }

    true
}

#[derive(Debug)]
pub struct Transaction {
    pub txid: String,
    pub fee: u64,
    pub weight: u64,
    pub parents: Vec<String>,
    pub children: Vec<String>,
}

pub fn load_mempool(file_path: &str) -> Result<HashMap<String, Transaction>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);

    let mut transactions = HashMap::new();
    let mut transaction_children = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let record: Vec<&str> = line.split(',').collect();

        if record.len() < 4 {
            continue;
        }

        let txid = record[0].trim().to_string();
        let fee = record[1].trim().parse::<u64>()?;
        let weight = record[2].trim().parse::<u64>()?;
        let parents: Vec<String> = record[3]
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if weight == 0 {
            return Err("Transaction weight cannot be zero".into());
        }

        transactions.insert(
            txid.clone(),
            Transaction {
                txid: txid.clone(),
                fee,
                weight,
                parents: parents.clone(),
                children: Vec::new(),
            },
        );

        for parent in parents {
            transaction_children
                .entry(parent)
                .or_insert_with(Vec::new)
                .push(txid.clone());
        }
    }

    for (parent_txid, children) in transaction_children {
        if let Some(parent_tx) = transactions.get_mut(&parent_txid) {
            parent_tx.children = children;
        }
    }

    Ok(transactions)
}

pub fn choose_transactions(
    sorted_transactions: Vec<String>,
    transactions: &HashMap<String, Transaction>,
    max_weight: u64,
) -> Vec<String> {
    let mut current_weight = 0;
    let mut included = HashSet::new();
    let mut selected = Vec::new();

    let mut tx_with_ratio: Vec<_> = sorted_transactions
        .iter()
        .map(|txid| {
            let tx = transactions.get(txid).unwrap();
            (txid.clone(), tx.fee as f64 / tx.weight as f64)
        })
        .collect();

    tx_with_ratio.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    for (txid, _) in tx_with_ratio {
        let tx = transactions.get(&txid).unwrap();

        let parents_included = tx
            .parents
            .iter()
            .filter(|p| transactions.contains_key(*p))
            .all(|p| included.contains(p));

        if !parents_included {
            continue;
        }

        if current_weight + tx.weight <= max_weight {
            selected.push(txid.clone());
            current_weight += tx.weight;
            included.insert(txid);
        }
    }

    selected
}

fn main() {
    let _current_dir = std::env::current_dir().unwrap();
    //println!("Current directory: {:?}", current_dir);
    let file_path: &str = "./mempool.csv";
    let output_path: &str = "./solution/block.txt";
    let max_block_weight = 4_000_000;

    if !File::open(file_path).is_ok() {
        panic!("File not found at path: {}", file_path);
    }

    let mempool_transactions = load_mempool(file_path).unwrap();
    let transaction_order = sort_transactions(&mempool_transactions);
    let block = choose_transactions(transaction_order, &mempool_transactions, max_block_weight);

    if !has_duplicate_transactions(block.clone()) {
        panic!("Duplicate transaction present in block");
    }

    let _ = save_block_to_file(block, &mempool_transactions, output_path);
}