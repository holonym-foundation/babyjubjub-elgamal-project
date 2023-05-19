use std::{env, collections::HashSet, str::FromStr};

use babyjubjub_rs::{Point};
use num_bigint::{BigInt};
use rocket::catcher;
use rocket::request::{FromRequest, Outcome};
use rocket::time::Instant;
use rocket::{State, serde::json::Json, response::status::BadRequest};
use rocket::{Request, Response, fairing::{Fairing, Info, Kind}, http::{Header, Status}};
use redis::{Commands, RedisError, Connection, Client};
// use rocket_contrib::json::Json;use std::env;
#[macro_use] extern crate rocket;

pub struct Cors;
const ALLOW_ORIGINS: [&'static str; 5] = ["https://silkwallet.net", "https://silksecure.net","http://localhost:3000", "http://localhost:3001", "https://silk-delta.vercel.app"];

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

const REQUESTS_PER_IP_PER_INTERVAL: u8 = 5;
const TOTAL_REQUESTS_PER_INTERVAL: usize = 1000;
const INTERVAL: usize = 60; // seconds

#[derive(Debug)]
pub struct RateLimit {
    remaining: u8,
}

#[derive(Debug)]
pub enum RateLimitError {
    TooManyRequests,
    IsntIPv4,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RateLimit {
    type Error = RateLimitError;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let addr = request.remote().unwrap();
        let ip = addr.ip();
        println!("IP: {:?}", ip);
        if !addr.is_ipv4() {
            return Outcome::Failure((Status::TooManyRequests, RateLimitError::IsntIPv4));
        }
        // let redis = request.guard::<State<&mut Connection>>();
        // let redis = request.rocket().state::<&mut redis::Connection>().unwrap();
        let client = request.rocket().state::<redis::Client>().unwrap();
        let now = Instant::now();
        let mut redis = client.get_connection().unwrap();
        println!("time to get redis connection: {:?}", now.elapsed());

        let recent_requests: u8 = match redis.get::<String,u8>(ip.to_string()) {
            Ok(num) => { 
                let _: () = redis.incr(ip.to_string(), 1).unwrap();
                num
            },
            RedisError =>  { 
                let _: String = redis.set(ip.to_string(), 1).unwrap(); 
                0
            }
        };
        
        Outcome::Success(RateLimit { remaining: 69 })
    }
}

#[catch(429)]
fn rate_limit(r: &Request) -> &'static str {
    "Too many requests OR request is not from an IPv4 address"
}

// this route is solely so that a TLS connection can be started early before any user action and automatically cached by both parties. This avoids the handshake latency overhead when the user requests the OPRF
#[get("/")]
fn do_nothing(r: RateLimit) -> &'static str { println!("remaining requests: {:?}", r); "GM" }

#[post("/oprf", format = "json", data = "<point>")]
fn index(privkey: &State<BigInt>, point: Json<Point>) -> Result<String, BadRequest<&'static str>> {
    // Check it is safe to proceed, i.e. point is on the curve and in subgroup
    if !point.on_curve() {
        return Err(BadRequest(Some("Not on curve")));
    }

    // Note: in_subgroup just checks that order of the point is the order of the subgroup
    if !point.in_subgroup() {
        return Err(BadRequest(Some("Not in subgroup")));
    }

    let result = point.mul_scalar(&privkey);
    Ok(serde_json::to_string(&result).unwrap())
    // format!("Hello, world! my private key is {}. you want me to multiply it by {:?}", privkey, point)
}

#[launch]
fn rocket() -> _ {
    // Get the private key env var
    let privkey: BigInt = env::var("OPRF_KEY")
        .expect("OPRF_KEY must be an environment variable. It should be a decimal string representing a random integer between 0 and the order of the curve's subgroup.")
        .parse::<BigInt>()
        .unwrap();
    let redis = redis::Client::open("redis://127.0.0.1")
                        .unwrap();

    // let mut client = redis
    //                     .get_connection()
    //                     .unwrap();

    // let _ : redis::RedisResult<String> = redis.set("redisworks", "yes");
    // let result: String = redis.get("redisworks").unwrap();
    // assert_eq!(result, "yes", "could not connect to redis");
    rocket::build()
    .manage(privkey)
    .manage(redis)
    .attach(Cors)
    .mount("/", routes![index, do_nothing])
    .register("/", catchers![rate_limit])
}
