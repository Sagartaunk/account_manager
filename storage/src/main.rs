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
                    .route("/admin_get_tokens" , web::post().to(admin_get_tokens))
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
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (email TEXT NOT NULL, password TEXT NOT NULL , Creation TEXT NOT NULL, TOKEN TEXT PRIMARY KEY , Type TEXT NOT NULL )" , ()).unwrap();
    match conn.execute("INSERT INTO accounts (email, password, Creation, TOKEN, Type) VALUES (?1, ?2, ?3, ?4, ?5)" , (&account.email, &account.password, &account.date, &account.token, &account.account_type)) {
        Ok(rows_updated) => {
            if rows_updated == 0 {
                log::warn!("Failed to create account for {}", account.token);
                HttpResponse::NotFound().body("Failed to create account")
            } else {
                log::info!("Succesfully created account for {} ", &account.token[..5]);
                HttpResponse::Ok().finish()
            }
        }
        Err(e) => {
            log::error!("Failed to update data: {}", e);
            HttpResponse::InternalServerError().body(format!("Database error: {}", e))
        }
    }
}

async fn admin_get_tokens(_ : web::Json<String>) -> HttpResponse {
    log::info!("Admin requested tokens");
    let conn = match rusqlite::Connection::open("accounts.db") {
        Ok(conn) => conn,
        Err(_) => {
            File::create("accounts.db").unwrap();
            rusqlite::Connection::open("accounts.db").unwrap()
        }
    };
    
    let mut stmt = match conn.prepare("SELECT TOKEN FROM accounts") {
        Ok(stmt) => stmt,
        Err(e) => {
            log::error!("SQL prepare error: {}", e);
            return HttpResponse::InternalServerError().finish();
        },
    };

    let result: Vec<String> = match stmt.query_map([], |row| {
        let token: String = row.get(0)?;
        Ok(token)
    }) {
        Ok(mapped_rows) => {
            let mut tokens = Vec::new();
            for row in mapped_rows {
                match row {
                    Ok(token) => tokens.push(token),
                    Err(e) => {
                        log::error!("Error mapping row: {}", e);
                        return HttpResponse::InternalServerError().finish();
                    }
                }
            }
            tokens
        }
        Err(e) => {
            log::error!("Query error: {}", e);
            return HttpResponse::InternalServerError().finish();
        },
    };
    
    log::info!("Retrieved {} tokens", result.len());
    HttpResponse::Ok().json(result)
}