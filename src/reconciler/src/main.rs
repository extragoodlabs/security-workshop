use anyhow::{Error, Result};
use config::Config;
use itertools::Itertools;
use serde::Deserialize;
use std::collections::HashMap;
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

fn get_user_ids(base_url: &Url) -> Result<Vec<String>> {
    let mut url = base_url.clone();
    url.set_path("/users");
    url.set_query(Some("fields=id"));

    let body: Response = reqwest::blocking::ClientBuilder::new()
        .build()?
        .get(url)
        .send()?
        .json()?;

    match body {
        Response::IdList(id_list) => {
            let ids = id_list.into_iter().map(|x| x.id.to_string()).collect();
            Ok(ids)
        }
        Response::Error { error } => Err(Error::msg(error)),
        _ => Err(Error::msg("unexpected user response type")),
    }
}

fn get_transaction_amounts(base_url: &Url) -> Result<Vec<Account>> {
    let mut url = base_url.clone();
    url.set_path("/transactions");
    let body: Response = reqwest::blocking::ClientBuilder::new()
        .build()?
        .get(url)
        .send()?
        .json()?;

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
                        amount,
                    }
                })
                .collect();
            Ok(amounts)
        }
        Response::Error { error } => Err(Error::msg(error)),
        _ => Err(Error::msg("unexpected transaction response type")),
    }
}

fn reconcile_accounts(user_ids: Vec<String>, accounts: Vec<Account>) {
    println!("found {:?} known users", user_ids.len());
    // do some heavy reporting here
    println!("reconciled {:?} accounts", accounts.len());
}

fn main() -> Result<()> {
    let config_file = std::env::var("APP_CONFIG_FILE").unwrap_or("settings.json".into());

    let config: HashMap<String, String> = Config::builder()
        .add_source(config::File::with_name(&config_file))
        .add_source(config::Environment::with_prefix("APP"))
        .build()?
        .try_deserialize()?;
    println!("settings: {:?}", config);

    let api_url = config.get("api_url").unwrap();
    let base_url = Url::parse(api_url).unwrap();

    let ids = get_user_ids(&base_url)?;
    let accounts = get_transaction_amounts(&base_url)?;
    reconcile_accounts(ids, accounts);
    Ok(())
}
