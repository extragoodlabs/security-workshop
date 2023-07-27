use itertools::Itertools;
use serde::Deserialize;
use std::error::Error;
use url::Url;

#[derive(Deserialize, Debug)]
struct User {
    id: i32,
    credit_card: String,
    currency: String,
    email: String,
    is_active: bool,
    country: String,
    num_logins: i32,
    password_hash: String,
    username: String,
    created_at: String,
}

#[derive(Deserialize, Debug)]
struct Transaction {
    id: i32,
    amount: f64,
    currency: String,
    description: String,
    timestamp: String,
    user_id: i32,
}

#[derive(Deserialize, Debug)]
struct IdValue {
    id: i32,
}

#[derive(Debug)]
struct Account {
    id: String,
    amount: f64,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum Response {
    User(User),
    Transaction(Transaction),
    UserList(Vec<User>),
    TransactionList(Vec<Transaction>),
    IdList(Vec<IdValue>),
    Error { error: String },
}

fn get_user_ids(base_url: &Url) -> Result<Vec<String>, Box<dyn Error>> {
    let mut url = base_url.clone();
    url.set_path("/users");
    url.set_query(Some("fields=id"));
    let body: Response = reqwest::blocking::get(url)?.json()?;

    match body {
        Response::IdList(id_list) => {
            let ids = id_list.into_iter().map(|x| x.id.to_string()).collect();
            Ok(ids)
        }
        Response::Error { error } => Err(Box::<dyn Error>::from(error)),
        _ => Err(Box::<dyn Error>::from("unexpected user response type")),
    }
}

fn get_transaction_amounts(base_url: &Url) -> Result<Vec<Account>, Box<dyn Error>> {
    let mut url = base_url.clone();
    url.set_path("/transactions");
    let body: Response = reqwest::blocking::get(url)?.json()?;

    match body {
        Response::TransactionList(mut transactions) => {
            transactions.sort_by_key(|t| t.user_id);
            let amounts = transactions
                .into_iter()
                .group_by(|t| t.user_id)
                .into_iter()
                .map(|(user_id, transactions)| {
                    let amount = transactions.map(|t| t.amount).sum();
                    Account {
                        id: user_id.to_string(),
                        amount: amount,
                    }
                })
                .collect();
            Ok(amounts)
        }
        Response::Error { error } => Err(Box::<dyn Error>::from(error)),
        _ => Err(Box::<dyn Error>::from(
            "unexpected transaction response type",
        )),
    }
}

fn reconcile_accounts(user_ids: Vec<String>, accounts: Vec<Account>) {
    println!("found {:?} known users", user_ids.len());
    // do some heavy reporting here
    println!("reconciled {:?} accounts", accounts.len());
}

fn main() -> Result<(), Box<dyn Error>> {
    // TODO: pull the API URL from a config
    let base_url = Url::parse("http://localhost:3000").unwrap();

    let ids = get_user_ids(&base_url)?;
    let accounts = get_transaction_amounts(&base_url)?;
    reconcile_accounts(ids, accounts);
    Ok(())
}
