pub mod middle{
    use actix_web::{dev::ServiceRequest, Error, HttpResponse};
use actix_web::dev::{Service, Transform, ServiceResponse};
use futures::future::{ok, Ready};
use futures::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use actix_web::body::BoxBody;

pub struct Middleware;

impl<S> Transform<S, ServiceRequest> for Middleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = MiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(MiddlewareService { service })
    }
}

pub struct MiddlewareService<S> {
    service: S,
}


impl<S> Service<ServiceRequest> for MiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .map(|header| header.trim_start_matches("Bearer "))
            .unwrap_or("");

        

        let validation = match token {
            "this_is_a_secure_token" => Ok(()), //Replace with token or validation logic 
            _ => Err("Invalid token"),
        };

        if validation.is_ok() {
            let fut = self.service.call(req);
            Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            })
        } else {
            let response = HttpResponse::Unauthorized()
                .content_type("text/plain")
                .body("Access denied: Unauthorized request");
            Box::pin(async move { Ok(req.into_response(response.map_into_boxed_body())) })
        }
    }
}
}