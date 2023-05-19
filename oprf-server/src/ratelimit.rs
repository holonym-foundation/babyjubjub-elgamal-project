use redis::{Commands, RedisError, Client};
use rocket::http::Status;
use rocket::request::{Request, FromRequest, Outcome};

const REQUESTS_PER_IP_PER_INTERVAL: u8 = 7;
// const TOTAL_REQUESTS_PER_INTERVAL: usize = 1000;
const INTERVAL: usize = 30; // seconds

#[derive(Debug)]
#[allow(dead_code)]
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
        let ip = request.remote().unwrap().ip();
        if !ip.is_ipv4() {
            return Outcome::Failure((Status::TooManyRequests, RateLimitError::IsntIPv4));
        }
        
        let client = request.rocket().state::<redis::Client>().unwrap();
        let mut redis = client.get_connection().unwrap();

        let recent_requests: u8 = match redis.get::<String,u8>(ip.to_string()) {
            Ok(num) => { 
                let _: () = redis.incr(ip.to_string(), 1).unwrap();
                num
            },
            Err(_) =>  { 
                let _: () = redis.set_ex(ip.to_string(), 1, INTERVAL).unwrap(); 
                0
            }
        };
        
        
        if recent_requests >= REQUESTS_PER_IP_PER_INTERVAL {
            Outcome::Failure((Status::TooManyRequests, RateLimitError::TooManyRequests))
        } else {
            Outcome::Success(RateLimit { remaining: REQUESTS_PER_IP_PER_INTERVAL - recent_requests - 1 })
        }
        
    }
}

#[catch(429)]
pub fn rate_limit(_: &Request) -> &'static str {
    "Too many requests OR request is not from an IPv4 address"
}

pub fn get_redis_client() -> Result<Client, RedisError> {
    redis::Client::open("redis://127.0.0.1")
}