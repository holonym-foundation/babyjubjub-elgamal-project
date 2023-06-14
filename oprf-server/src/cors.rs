use rocket::{Request, Response, fairing::{Fairing, Info, Kind}, http::{Header, Status}};

pub struct Cors;
const ALLOW_ORIGINS: [&'static str; 6] = ["https://silkwallet.net", "https://silksecure.net", "https://staging.silksecure.net", "http://localhost:3000", "http://localhost:3001", "https://silk-delta.vercel.app"];

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Fairing to add the CORS headers",
            kind: Kind::Response
        }
    }
    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        let _origin = match _request.headers().get_one("origin") {
            Some(origin) => origin,
            None => "null"
        };
        let allow_origin = if ALLOW_ORIGINS.contains(&_origin) { _origin } else { "null" };

        response.set_status(Status::new(200));
        
        response.set_header(Header::new("Access-Control-Allow-Origin", allow_origin)); //CHANGE THIS TO ONLY SAFE SITES
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));

    }
}
