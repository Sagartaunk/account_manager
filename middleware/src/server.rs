use reqwest::Client;
use serde_json::{json ,Value};
use actix_web::{web , HttpResponse};
use serde::{Deserialize, Serialize};
use chrono::{format, Local};
use rand::{distributions::Alphanumeric, Rng};
use log;
use bcrypt::{verify  , hash , DEFAULT_COST };
use std::pin::Pin;
use std::sync::{Arc , Mutex};
use aes_gcm::{Aes256Gcm , Key , Nonce , KeyInit , aead::Aead};
use hex;

fn storage_ip() -> String {
    let ip = String::from("http://192.168.1.26:51001");
    ip
}
fn storage_token() -> String {
    let token = String::from("Bearer this_is_a_secure_token");
    token
}
fn database_ip() -> String {
    let ip = String::from("http://192.168.1.26:51000");
    ip
}
fn database_token() -> String {
    let token = String::from("Bearer this_is_a_secure_token");
    token
}





#[derive(Debug , Serialize , Deserialize , Clone)]
pub struct Login {
    pub email : String,
    pub password : String,

}
#[derive(Debug , Serialize , Deserialize , Clone)]
pub struct Data_login {
    pub email : String,
    pub password : String,
    pub token : String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Data_register {
    pub email: String,
    pub password: String,
    pub date: String,
    pub token: String, 
    pub account_type: String,
}

#[derive(Debug , Serialize , Deserialize , Clone)]
pub struct Database {
    pub token : String,
    pub data : String,
} 
#[derive(Debug , Serialize , Deserialize , Clone)]
struct Account {
    username : String,
    website : String,
    password : String,
}
#[derive(Debug , Serialize , Deserialize , Clone)]
struct Accounts{
    username : String,
    website : String,
}
#[derive(Debug , Serialize , Deserialize , Clone)]
pub struct Data {
    email : String, 
    password : String,
    data : String
}

async fn storage_get(email : String) -> Value {
    let client = Client::new();
    let result;
    let res = client.post(format!("{}/api/get" , storage_ip())).header("Authorization" , storage_token()).header("Content-Type" , "application/json").body(format!("\"{}\"", email)).send().await;
    match res {
        Ok(response) => {
            if response.status().is_success() {
                let body : Value = response.json().await.unwrap();
                result = body
            } else {
                result = json!({"error": "Request failed"});
            }
        },
        Err(_) => {
            result = json!({"error": "Request failed"})
        }
    }
    result

}
async fn account_create(data: Data_register) {
    let data = Data_register{
        email: data.email,
        password: hash(data.password, DEFAULT_COST).unwrap(),
        date: data.date,
        token: data.token,
        account_type: data.account_type,
    };
    let client = Client::new();
    let res1 = client.post(format!("{}/api/create", storage_ip()))
        .header("Authorization", storage_token())
        .header("Content-Type", "application/json")
        .json(&data)
        .send()
        .await;
    
    match res1 {
        Ok(response) => {
            if response.status().is_success() {
                log::info!("Account created successfully");
            } else {
                log::error!("Failed to create account: HTTP {}", response.status());
            }
        },
        Err(e) => {
            log::error!("Error: {}", e);
            log::error!("Failed to create account");            
        }
    }
    

    let db_data = Database { 
        token: data.token.clone(),
        data: String::new(),
    };

    let client = Client::new();
    let res2 = client.post(format!("{}/api/create", database_ip()))
        .header("Authorization", database_token())
        .header("Content-Type", "application/json")
        .json(&db_data)
        .send()
        .await;
    
    match res2 {
        Ok(response) => {
            if response.status().is_success() {
                log::info!("Database entry created successfully");
            } else {
                log::error!("Failed to create database entry: HTTP {}", response.status());
            }
        },
        Err(e) => {
            log::error!("Error: {}", e);
        }
    }
}

async fn data_get(token: String) -> Database {
    let client = Client::new();
    
    let res = client.post(format!("{}/api/get", database_ip()))
        .header("Authorization", database_token())
        .header("Content-Type", "application/json")
        .body(token.clone())
        .send()
        .await;
    
    let mut database = Database {
        token: token.clone(), 
        data: String::new(),
    };
    match res {
        Ok(response) => {
            if response.status().is_success() {
                let body: Value = response.json().await.unwrap();
                if let Some(data) = body.get(0).and_then(|item| item.get("DATA")).and_then(|item| item.as_str()){
                    database.data = data.to_string();
                    log::info!("Data: {}", database.data);
                } else {
                    database.data = String::new();
                    log::error!("No data found for token: {}", token);
                }
            } else {
                log::error!("Failed to get data: HTTP {}", response.status());
            }
        },
        Err(e) => {
            log::error!("Error: {}", e);
        }
    }
    
    database
}

pub async fn login(login: web::Json<Login>) -> HttpResponse {  
    let (data , error) = get_token(login.clone()).await;
    if error {
        log::error!("{}" , data);
        return HttpResponse::InternalServerError().finish();
    }else{
        return HttpResponse::Ok().body("Login successful");
    }

}

pub async fn register(register: web::Json<Login>) -> HttpResponse {
    let email = register.email.clone();
    let password = register.password.clone();
    let date = Local::now().date_naive().to_string();
    let token = token_gen(generator()).await;
    
    
    let data_register = Data_register {
        email,
        password,
        date,
        token: token.clone(),
        account_type: "user".to_string(),
    };
    
    account_create(data_register).await;
    HttpResponse::Ok().finish()
}
fn generator() -> String {
    let token = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect::<String>();
    token
}

async fn token_gen(token : String) -> String {
    let mut pass = Arc::new(Mutex::new(String::new()));
    let token = Arc::new(Mutex::new(token));
    Box::pin(async{  
        let client = Client::new();
        let res = client.post(format!("{}/api/get", database_ip()))
            .header("Authorization", database_token())
            .header("Content-Type", "application/json")
            .body(format!("\"{}\"", token.lock().unwrap().clone()))
            .send()
            .await;
        let mut pass = pass.lock().unwrap();
        if res.unwrap().status().is_success() {
            pass.push_str(token_gen(generator()).await.as_str());
        }else {
            pass.push_str(token.lock().unwrap().clone().as_str());
        }
    }).await;
    pass.lock().unwrap().clone()
}

pub async fn get_data(login: web::Json<Login>) -> HttpResponse {  
    let (token , error) = get_token(login.clone()).await;
    match error {
        true => {
            log::error!("{}", token);
            return HttpResponse::InternalServerError().finish();
        },
        false => {
            log::info!("Running get_data");
        let data = data_get(token.clone()).await;
        if data.data.is_empty() {
            log::error!("No data found for token: {}", token);
            return HttpResponse::InternalServerError().body("No data found");
        }else{
            let data: Vec<String> = data.data.split(',').map(|s| s.to_string()).collect();
            let mut accounts = String::new();
            for data in data {
                let values : Vec<&str> = data.split(':').collect();
                let account = Accounts {
                    username: values[0].to_string(),
                    website: values[1].to_string(),
                };
                accounts.push_str(&format!("Username: {}, Website: {}\n", account.username, account.website));
            }
            return HttpResponse::Ok().json(accounts);
        }
    }
    }
}

pub async fn add_data(data : web::Json<Data>) -> HttpResponse {
    let login = Login {
        email : data.email.clone(),
        password : data.password.clone()
    };
    let (token , error) = get_token(login.clone()).await;
    if error {
        log::error!("{}", token);
        return HttpResponse::InternalServerError().finish();
    }
    else {
        let saved_data = data_get(token.clone()).await;
        let data : Vec<String> = data.data.split(':').map(|s| s.to_string()).collect();
        log::info!("Data: {:?}", data.clone());
        let account = Account {
            username: data[0].to_string(),
            website: data[1].to_string(),
            password: encrypt(token.clone(), data[2].to_string()),
        };
        let to_save =  format!("{}{}:{}:{}," ,saved_data.data ,  account.username , account.website , account.password);
        log::info!("Data to save: {}", to_save.clone());
        let to_save = Database {
            token: token.clone(),
            data: to_save,
        };
        log::info!("Data to save: {}", to_save.data.clone());
        let client = Client::new();
        let res = client.post(format!("{}/api/add", database_ip()))
            .header("Authorization", database_token())
            .header("Content-Type", "application/json")
            .json(&to_save)
            .send()
            .await;
        match res {
            Ok(response) => {
                if response.status().is_success() {
                    return HttpResponse::Ok().body("Data added successfully");
                } else {
                    log::error!("Error: {}", response.status());
                    return HttpResponse::InternalServerError().finish();
                }
            },
            Err(e) => {
                log::error!("Error: {}", e);
                return HttpResponse::InternalServerError().finish();
            }
        }
    }    
}

pub async fn get_token(login : Login) -> (String , bool) {  
    let data = storage_get(login.email.clone()).await;
    
    if data == json!({"error": "Request failed"}) {
        log::error!("Storage service request failed");
        return (String::from("Storage service request failed") , true);
    }

    if !data.is_array() || data.as_array().unwrap().is_empty() {
        log::error!("No account found for email: {}", login.email);
        return (String::from("No account found for email") , true);
    }
    let account = &data[0];
    
    match account.get("password") {
        Some(password_val) => {
            let password = password_val.as_str().unwrap_or("");
            if verify(login.password.clone() , password).unwrap_or(false) {
                match account.get("token") {
                    Some(token_val) => {
                        let token = token_val.to_string();
                        (token , false)
                    },
                    None => {
                        (String::from("Token not found in account data") , true)
                    }
                }
            } else {
                (String::from("Invalid password") , true)
            }
        },
        None => {
            (String::from("Password not found in account data") , true)
        }
    }
}
fn encrypt(key : String , data : String) -> String {
    let key = key_gen(key);
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); 
    let ciphertext = cipher.encrypt(nonce, data.as_bytes()).expect("encryption failure!");
    hex::encode(ciphertext)
}
fn decrypt(key : String , data : String) -> String {
    let key = key_gen(key);
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let data = hex::decode(data).expect("Failed to decode hex");
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce");
    let plaintext = cipher.decrypt(nonce, data.as_ref()).expect("decryption failure!");
    String::from_utf8(plaintext).expect("Failed to convert to string")
}

fn key_gen(k : String) -> [u8 ; 32] {
    let k = k.as_bytes();
    let mut k1 = [0u8; 32];
    for i in 0..32 {
        k1[i] = k[i % k.len()];
    }
    k1
}