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
    data : Option<Vec<u8>>
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
            )
    }).bind(bind_address)?
    .run()
    .await
}

async fn get_data(token : web::Json<String>) -> HttpResponse {
    let conn = match rusqlite::Connection::open("data.db") {
        Ok(conn) => conn,
        Err(_) => {
            File::create("data.db").unwrap();
            rusqlite::Connection::open("data.db").unwrap()
        }
    };
    
    let mut stmt = match conn.prepare("SELECT * FROM data WHERE TOKEN = (?1)") {
        Ok(stmt) => stmt,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let result = match stmt.query_map([token.as_str()], |row| {
        let token: String = row.get(0)?;
        let data: Option<Vec<u8>> = row.get(1)?;
        
        Ok(Data { token, data })
    }) {
        Ok(mapped_rows) => {
            let mut datas = Vec::new();
            for row in mapped_rows {
                match row {
                    Ok(data) => datas.push(data),
                    Err(_) => return HttpResponse::InternalServerError().finish(),
                }
            }
            datas
        }
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
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
    conn.execute("CREATE TABLE IF NOT EXISTS data (TOKEN TEXT PRIMARY KEY, DATA BLOB )" , ()).unwrap();
    match conn.execute("INSERT INTO data (TOKEN , DATA) VALUES (?1, ?2)" , (&data.token, &data.data)) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(_) => HttpResponse::InternalServerError().finish()
    }
}