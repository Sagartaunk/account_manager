use reqwest::Client;
use serde_json::{json ,Value};
use actix_web::{web , HttpResponse};
use serde::{Deserialize, Serialize};
use chrono::Local;
use rand::{distributions::Alphanumeric, Rng};
use log;
use aes_gcm::{self , KeyInit , aead::Aead};

fn storage_ip() -> String {
    let ip = String::from("http://10.0.0.238:51001");
    ip
}
fn storage_token() -> String {
    let token = String::from("Bearer this_is_a_secure_token");
    token
}
fn database_ip() -> String {
    let ip = String::from("http://10.0.0.238:51000");
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
    pub data : Option<Vec<u8>>,
} 
#[derive(Debug , Serialize , Deserialize , Clone)]
pub struct DatabasD {
    pub token : String,
    pub data : Option<Vec<u8>>,
} 


async fn storage_get(email : String) -> Value {
    let client = Client::new();
    let mut result;
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
        password: bcrypt::hash(data.password, bcrypt::DEFAULT_COST).unwrap(),
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
        data: None,
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
        .body(format!("\"{}\"", token))
        .send()
        .await;
    
    let mut database = Database {
        token: token, 
        data: None,
    };
    
    match res {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<Value>().await {
                    Ok(data) => {
                        if data.is_array() && !data.as_array().unwrap().is_empty() {
                            if let Some(data_obj) = data[0].get("data") {
                                if let Some(binary_data) = data_obj.as_array() {
                                    let bytes: Vec<u8> = binary_data.iter()
                                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                                        .collect();
                                    database.data = Some(bytes);
                                }
                            }
                        }
                    },
                    Err(e) => log::error!("Failed to parse JSON: {}", e),
                }
            }
        },
        Err(e) => {
            log::error!("Error: {}", e);
        }
    }
    
    database
}

pub async fn login(login: web::Json<Login>) -> HttpResponse {  
    let data = storage_get(login.email.clone()).await;
    
    if data == json!({"error": "Request failed"}) {
        log::error!("Storage service request failed");
        return HttpResponse::InternalServerError().finish();
    }

    if !data.is_array() || data.as_array().unwrap().is_empty() {
        log::error!("No account found for email: {}", login.email);
        return HttpResponse::Unauthorized().finish();
    }
    let account = &data[0];
    
    match account.get("password") {
        Some(password_val) => {
            let password = password_val.as_str().unwrap_or("");
            if bcrypt::verify(login.password.clone() , password).unwrap_or(false) {
                match account.get("token") {
                    Some(token_val) => {
                        let token = token_val.as_str().unwrap_or("");
                        let data = data_get(token.to_string()).await;
                        HttpResponse::Ok().json(data)
                    },
                    None => {
                        log::error!("Token not found in account data");
                        HttpResponse::InternalServerError().finish()
                    }
                }
            } else {
                HttpResponse::Unauthorized().finish()
            }
        },
        None => {
            log::error!("Password not found in account data");
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub async fn register(register: web::Json<Login>) -> HttpResponse {
    let email = register.email.clone();
    let password = register.password.clone();
    let date = Local::now().date_naive().to_string();
    let token = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect::<String>();
    
    
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