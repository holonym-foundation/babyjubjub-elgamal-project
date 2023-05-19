use redis::{Commands, RedisError, Connection, Client};
use rocket::catcher;
use rocket::http::Status;
use rocket::request::{Request, FromRequest, Outcome};
const REQUESTS_PER_IP_PER_INTERVAL: u8 = 3;
// const TOTAL_REQUESTS_PER_INTERVAL: usize = 1000;
const INTERVAL: usize = 9; // seconds

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
        // let now = Instant::now();
        let mut redis = client.get_connection().unwrap();
        // println!("time to get redis connection: {:?}", now.elapsed());

        // let _: () = redis.set_ex(ip.to_string(), 0, INTERVAL).unwrap();
        let recent_requests: u8 = match redis.get::<String,u8>(ip.to_string()) {
            Ok(num) => { 
                let _: () = redis.incr(ip.to_string(), 1).unwrap();
                num
            },
            RedisError =>  { 
                let _: () = redis.set_ex(ip.to_string(), 1, INTERVAL).unwrap(); 
                0
            }
        };
        
        
        if recent_requests >= REQUESTS_PER_IP_PER_INTERVAL {
            Outcome::Failure((Status::TooManyRequests, RateLimitError::TooManyRequests))
        } else {
            Outcome::Success(RateLimit { remaining: recent_requests })
        }
        
    }
}

#[catch(429)]
pub fn rate_limit(r: &Request) -> &'static str {
    "Too many requests OR request is not from an IPv4 address"
}

pub fn get_redis_client() -> Result<Client, RedisError> {
    redis::Client::open("redis://127.0.0.1")
}