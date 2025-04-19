use rusqlite::{self};
use actix_web::{web, App, HttpServer , HttpResponse};
use std::fs::File;
use env_logger;
use log;
use local_ip_address::local_ip;
use serde::{Serialize, Deserialize};
use storage::middle::Middleware;

#[derive(Debug , Serialize , Deserialize , Clone)]
struct Account {
    email : String,
    password : String,
    date : String,
    token : String ,
    account_type : String, 
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let device_ip = local_ip().unwrap();
    let bind_address = format!("{}:51001", device_ip);
    log::info!("Starting at http://{}", bind_address);
    HttpServer::new(|| {
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .service(
                web::scope("/api")
                    .wrap(Middleware)
                    .route("/create", web::post().to(create_data))
                    .route("/get" , web::post().to(get_data))
            )
    }).bind(bind_address)?
    .run()
    .await
}




async fn get_data(email : web::Json<String>) -> HttpResponse {
    let conn = match rusqlite::Connection::open("accounts.db") {
        Ok(conn) => conn,
        Err(_) => {
            File::create("accounts.db").unwrap();
            rusqlite::Connection::open("accounts.db").unwrap()
        }
    };
    
    let mut  stmt = match conn.prepare("SELECT * FROM accounts WHERE email = (?1)") {
        Ok(stmt) => stmt,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let result = match stmt.query_map([email.as_str()], |accounts| {
        Ok(Account {
            email: accounts.get(0)?,
            password: accounts.get(1)?,
            date: accounts.get(2)?,
            token: accounts.get(3)?,
            account_type: accounts.get(4)?,
        })
    }) {
        Ok(mapped_rows) => {
            let mut accounts = Vec::new();
            for row in mapped_rows {
                match row {
                    Ok(account) => accounts.push(account),
                    Err(_) => return HttpResponse::InternalServerError().finish(),
                }
            }
            accounts
        }
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    HttpResponse::Ok().json(result)
}

async fn create_data(account : web::Json<Account>) -> HttpResponse {
    let conn = match rusqlite::Connection::open("accounts.db") {
        Ok(conn) => conn,
        Err(_) => {
            File::create("accounts.db").unwrap();
            rusqlite::Connection::open("accounts.db").unwrap()
        }
    };
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (email TEXT NOT NULL, password TEXT NOT NULL , Creation TEXT NOT NULL, TOKEN  PRIMARY KEY , Type TEXT NOT NULL )" , ()).unwrap();
    match conn.execute("INSERT INTO accounts (email, password, Creation, TOKEN, Type) VALUES (?1, ?2, ?3, ?4, ?5)" , (&account.email, &account.password, &account.date, &account.token, &account.account_type)) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(_) => HttpResponse::InternalServerError().finish()
    }
}

