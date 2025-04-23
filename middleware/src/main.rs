
use encryptor::{middleware::Middleware , server::{login , register}};
use actix_web::{web, App, HttpServer};
use env_logger;
use log;
use local_ip_address::local_ip;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let device_ip = local_ip().unwrap();
    let bind_address = format!("{}:51020", device_ip);
    log::info!("Starting at http://{}", bind_address);
    HttpServer::new(|| {
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .service(
                web::scope("/api")
                    .wrap(Middleware)
                    .route("/login", web::post().to(login))
                    .route("/register" , web::post().to(register))
            )
    }).bind(bind_address)?
    .run()
    .await
}