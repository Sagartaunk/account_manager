use rusqlite::{self};
use actix_web::{web, App, HttpServer , HttpResponse};
use std::fs::File;
use env_logger;
use log;
use local_ip_address::local_ip;
use serde::{Serialize, Deserialize};
use database::middle::Middleware;

#[derive(Debug , Serialize , Deserialize , Clone)]
struct Data {
    token : String,
    data : String
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let device_ip = local_ip().unwrap();
    let bind_address = format!("{}:51000", device_ip);
    log::info!("Starting at http://{}", bind_address);
    HttpServer::new(|| {
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .service(
                web::scope("/api")
                    .wrap(Middleware)
                    .route("/create", web::post().to(create_data))
                    .route("/get" , web::post().to(get_data))
                    .route("/add" , web::post().to(add_data))
            )
    }).bind(bind_address)?
    .run()
    .await
}

async fn get_data(token: web::Json<String>) -> HttpResponse {
    let conn = match rusqlite::Connection::open("data.db") {
        Ok(conn) => conn,
        Err(e) => {
            log::error!("Failed to open database: {}", e);
            return HttpResponse::InternalServerError().body("Database connection error");
        }
    };
    

    let token = token.trim_matches('"').to_string();
    log::debug!("Processing token: {}", token);
    
    let mut stmt = match conn.prepare("SELECT DATA FROM data WHERE TOKEN = (?1)") {
        Ok(stmt) => stmt,
        Err(e) => {
            log::error!("SQL prepare error: {}", e);
            return HttpResponse::InternalServerError().body("SQL preparation error");
        }
    };

    let result: Vec<String> = match stmt.query_map([token.as_str()], |row| {
        let data: String = row.get(0)?;
        Ok(data)
    }) {
        Ok(mapped_rows) => {
            let mut datas = Vec::new();
            for row in mapped_rows {
                match row {
                    Ok(data) => datas.push(data),
                    Err(e) => {
                        log::error!("Error retrieving data: {}", e);
                        return HttpResponse::InternalServerError().body(format!("Error: {}", e));
                    }
                }
            }
            datas
        }
        Err(e) => {
            log::error!("Query error: {}", e);
            return HttpResponse::InternalServerError().body("Query execution error");
        }
    };
    
    log::info!("Data for token {}: {:?}", token, result);
    HttpResponse::Ok().json(result)
}
async fn create_data(data : web::Json<Data>) -> HttpResponse {
    let conn = match rusqlite::Connection::open("data.db") {
        Ok(conn) => conn,
        Err(_) => {
            File::create("data.db").unwrap();
            rusqlite::Connection::open("data.db").unwrap()
        }
    };
    conn.execute("CREATE TABLE IF NOT EXISTS data (TOKEN TEXT PRIMARY KEY, DATA TEXT )" , ()).unwrap();
    match conn.execute("INSERT INTO data (TOKEN , DATA) VALUES (?1, ?2)" , (&data.token, &data.data)) {
        Ok(rows_updated) => {
            if rows_updated == 0 {
                log::warn!("Failed to create account for {}", data.token);
                HttpResponse::NotFound().body("Failed to create account")
            } else {
                log::info!("Succesfully created account for {} ", &data.token[..5]);
                HttpResponse::Ok().finish()
            }
        }
        Err(e) => {
            log::error!("Failed to update data: {}", e);
            HttpResponse::InternalServerError().body(format!("Database error: {}", e))
        }
    }
}

async fn add_data(data: web::Json<Data>) -> HttpResponse {
    let conn = match rusqlite::Connection::open("data.db") {
        Ok(conn) => conn,
        Err(e) => {
            log::error!("Failed to open database: {}", e);
            return HttpResponse::InternalServerError().body("Failed to connect to the database");
        }
    };
    let token = data.token.trim_matches('"').to_string();
    match conn.execute("UPDATE data SET DATA = (?1) WHERE TOKEN = (?2)", (&data.data, &token)) {
        Ok(rows_updated) => {
            if rows_updated == 0 {
                log::warn!("No rows updated. Token {} not found.", token);
                HttpResponse::NotFound().body("Token not found")
            } else {
                log::info!("Data updated for token starting with {}", &token[..5]);
                HttpResponse::Ok().finish()
            }
        }
        Err(e) => {
            log::error!("Failed to update data: {}", e);
            HttpResponse::InternalServerError().body(format!("Database error: {}", e))
        }
    }
}