use reqwest::Client;
use serde_json::{json ,Value};
use actix_web::{web, App, HttpServer , HttpResponse};
use serde::{Deserialize, Serialize};
use chrono::Local;
use rand::{distributions::Alphanumeric, Rng};
use log;
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
#[derive(Debug , Serialize , Deserialize , Clone)]
pub struct Data_register {
    pub email : String ,
    pub password : String,
    pub date: String,
    pub token : String,
    pub account_type : String,

}

#[derive(Debug , Serialize , Deserialize , Clone)]
pub struct Database {
    pub token : String,
    pub data : Option<Vec<u8>>,
} 


async fn storage_get(email : String) -> Value {
    let client = Client::new();
    let mut result;
    let res = client.post("http://192.168.1.101:1020/api/get").header("Authorization" , "Bearer this_is_a_secure_token").header("Content-Type" , "application/json").json(&json!(email)).send().await;
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
async fn account_create(data : Data_register) {
    let client = Client::new();

    //change the ip and the authorization token to your own
    let res1 = client.post("http://192.168.1.101:1020/api/create").header("Authorization" , "Bearer this_is_a_secure_token").header("Content-Type" , "application/json").json(&data).send().await;
    match res1 {
        Ok(response) => {
            if response.status().is_success() {}
        },
        Err(e) => {
            log::error!("Error: {}", e);
            log::error!("Failed to create account");            
        }
    }
    let data = Database{
        token: data.token.clone(),
        data: None,
    };

    let client = Client::new();
    let res2 = client.post("http://192.168.1.101:2050/api/create").header("Authorization" , "Bearer this_is_a_secure_token").header("Content-Type" , "application/json").json(&json!{data}).send().await;
    match res2 {
        Ok(response) => {
            if response.status().is_success() {}
        },
        Err(e) => {
            log::error!("Error: {}", e);
            log::error!("Failed to create account");            
        }
    }
}

async fn data_get(token : String) -> Database {
    let client = Client::new();
    let res = client.post("http://192.168.1.101:2050/api/get").header("Authorization" , "Bearer this_is_a_secure_token").header("Content-Type" , "application/json").json(&json!{token}).send().await;
    let mut database = Database{
        token : token.clone(),
        data : None,
    };
    match res {
        Ok(response) => {
            if response.status().is_success() {   
                let data : Value = response.json().await.unwrap();
                if let Some(bytes) = data["data"].as_array().map(|arr| {
                    arr.iter()
                       .filter_map(|v| v.as_u64().map(|n| n as u8))
                       .collect::<Vec<u8>>()
                }) {
                    database.data = Some(bytes);
                }
            }
        },
        Err(e) => {
            log::error!("Error: {}", e);
        }
    }
    
    database
}

pub async fn login (login : web::Json<Login>) -> HttpResponse{ //need to fix this block 
    let data = storage_get(login.email.clone()).await;
    if data == json!({"error": "Request failed"}) {
        HttpResponse::InternalServerError().finish()
    }
    else {
        let password = data["password"].as_str().unwrap_or("");
        log::info!("{}",password); //remove when done
        if password == login.password {
            let token = data["token"].as_str().unwrap_or("");
            let data = data_get(token.to_string()).await;
            HttpResponse::Ok().json(data)
        } else {
            HttpResponse::Unauthorized().finish()
        }
    }

}

pub async fn register(register : web::Json<Login>) -> HttpResponse {
    let email = register.email.clone();
    let password = register.password.clone();
    let date = Local::now().date_naive().to_string();
    let token = rand::thread_rng().sample_iter(&Alphanumeric).take(30).map(char::from).collect::<String>();
    let ttype = "user".to_string();
    let data_register = Data_register {
        email: email,
        password: password,
        token: token,
        date: date,
        account_type: ttype,
    };
    account_create(data_register).await;
    HttpResponse::Ok().finish()
}
