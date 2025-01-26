use std::{env, net::Ipv4Addr, path::PathBuf, process::Command};

use hmac::{digest::MacError, Mac};
use rocket::{
    data::{Limits, ToByteUnit},
    get,
    http::Status,
    launch, post,
    request::{FromRequest, Outcome},
    routes, Config, Request,
};

/// The string for the environment variable containing the secret.
const WEBHOOK_STRING: &str = "WEBHOOK_SECRET";
/// The name of the header sent by GitHub generated from the secret and payload.
const HEADER: &str = "X-Hub-Signature-256";
/// The path to the bash script to get executed on a valid post.
const SCRIPT_STRING: &str = "WEBHOOK_SCRIPT";

#[get("/")]
fn listen() -> String {
    "Urm, hi?\nHow did you get here?\nThis is an api for computers 'n' stuff, not for humans :P"
        .to_owned()
}

#[post("/", format = "json", data = "<user_input>")]
fn webhook_listen(signature: XHubSignature, user_input: String) -> Status {
    // Get script path
    let path = env::var(SCRIPT_STRING).clone().map(|string_path| {
        let mut path = PathBuf::new();
        path.push(string_path);
        path
    });
    let path = match path {
        Ok(path) => path,
        Err(err) => {
            eprintln!("Could not get script path from environment: {err}");
            return Status::InternalServerError;
        }
    };

    // Get secret
    let secret = match env::var(WEBHOOK_STRING).clone() {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("Could not get secret key from environment: {err}");
            return Status::InternalServerError;
        }
    };

    // Check if sent signature was produced from matching secret
    if let Err(err) = signature_matches(&secret, &user_input.to_string(), signature) {
        eprintln!("Signature Error: {err}");
        return Status::Unauthorized;
    };

    // Execute script
    match Command::new("bash").arg(path).spawn() {
        Ok(_) => {}
        Err(err) => {
            eprintln!("Could not execute bash script: {err}");
            return Status::InternalServerError;
        }
    };

    Status::Ok
}

/// The possible errors when checking that the received signature is correct.
#[derive(thiserror::Error, Debug)]
enum SignatureError {
    #[error("The received signature contained non-ascii chars.")]
    NotASCII,
    #[error("The received signature is not valid hexadecimal: {0}")]
    BadHex(#[from] hex::FromHexError),
    #[error("Error when validating signature: {0}")]
    ValidationError(#[from] MacError),
}

/// Check if the payload signature is generated from the given secret
fn signature_matches<'a>(
    secret: &str,
    payload: &str,
    signature: XHubSignature,
) -> Result<(), SignatureError> {
    let XHubSignature { signature } = signature;

    // Remove the "sha256=" from start of signature
    let hex_signature = signature
        .split_at_checked(7)
        .ok_or_else(|| SignatureError::NotASCII)?
        .1;

    // Using let binding to create longer lived value
    let binding = hex::decode(hex_signature)?;
    let raw_signature = binding.as_slice();

    Ok(
        hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
            .unwrap()
            .chain_update(payload)
            .verify_slice(raw_signature)?,
    )
}

/// The GitHub webhook payload signature
struct XHubSignature<'a> {
    signature: &'a str,
}

#[rocket::async_trait]
impl<'a> FromRequest<'a> for XHubSignature<'a> {
    type Error = ();

    async fn from_request(request: &'a Request<'_>) -> Outcome<Self, ()> {
        match request.headers().get_one(HEADER) {
            Some(signature) => Outcome::Success(Self { signature }),
            None => Outcome::Error((Status::BadRequest, ())),
        }
    }
}

#[launch]
fn launch() -> _ {
    // This way still allows for customistion via ENV.
    let config = Config::figment().merge((
        Config::LIMITS,
        Limits::new().limit("string", 32.kibibytes()),
    ));

    rocket::build()
        .configure(config)
        .mount("/", routes![listen, webhook_listen])
}

#[cfg(test)]
mod tests {
    use rocket::{http::Header, local::blocking::Client, uri};

    use super::*;

    #[test]
    fn no_env() {
        temp_env::with_vars_unset([WEBHOOK_STRING, SCRIPT_STRING], || {
            let client = Client::tracked(launch()).expect("valid rocket instance");
            let response = client
                .post(uri!(webhook_listen))
                .json(&"{}")
                .header(Header::new(HEADER, "N/A"))
                .dispatch();

            assert_eq!(response.status(), Status::InternalServerError);
        });
    }

    #[test]
    fn no_signature() {
        temp_env::with_vars(
            [(WEBHOOK_STRING, None), (SCRIPT_STRING, Some("script.sh"))],
            || {
                let client = Client::tracked(launch()).expect("valid rocket instance");
                let response = client
                    .post(uri!(webhook_listen))
                    .json(&"{}")
                    .header(Header::new(HEADER, "Not_A_Match"))
                    .dispatch();

                assert_eq!(response.status(), Status::InternalServerError);
            },
        );
    }

    #[test]
    fn no_script() {
        temp_env::with_vars(
            [
                (WEBHOOK_STRING, Some("Very Secure!")),
                (SCRIPT_STRING, None),
            ],
            || {
                let client = Client::tracked(launch()).expect("valid rocket instance");
                let response = client
                    .post(uri!(webhook_listen))
                    .json(&"{}")
                    .header(Header::new(HEADER, "Not_A_Match"))
                    .dispatch();

                assert_eq!(response.status(), Status::InternalServerError);
            },
        );
    }

    #[test]
    fn signature_generation() {
        signature_matches(
            "It's a Secret to Everybody",
            "Hello, World!",
            XHubSignature {
                signature:
                    "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
            },
        )
        .unwrap();
    }

    #[test]
    fn invalid_signature() {
        temp_env::with_vars(
            [
                (WEBHOOK_STRING, Some("Very Secure!")),
                (SCRIPT_STRING, Some("script.sh")),
            ],
            || {
                let client = Client::tracked(launch()).expect("valid rocket instance");
                let response = client
                    .post(uri!(webhook_listen))
                    .json(&"{}")
                    .header(Header::new(HEADER, "sha256=0123acd"))
                    .dispatch();

                assert_eq!(response.status(), Status::Unauthorized);
            },
        );
    }

    #[test]
    fn valid_request() {
        // Temp dir for bash script
        let temp_dir =
            tempdir::TempDir::new("webhook_handler-temp").expect("Able to create temp dir");

        // Write script
        let mut path = temp_dir.path().to_path_buf();
        path.push("test.sh");
        std::fs::write(
            &path,
            format!(
                // Switch to correct dir
                "cd {}; echo 'hi' > file.temp",
                temp_dir.path().to_str().expect("Valid Path")
            ),
        )
        .expect("Able to write test script");

        // Valid signature with valid bash script
        temp_env::with_vars(
            [
                (WEBHOOK_STRING, Some("VerySecure")),
                (SCRIPT_STRING, Some(path.to_str().expect("Valid Path"))),
            ],
            || {
                let client = Client::tracked(launch()).expect("valid rocket instance");
                let response = client
                    .post(uri!(webhook_listen))
                    .json(&"{\"test\": 1}")
                    .header(Header::new(
                        HEADER,
                        "sha256=f5cf34a2c036452fd80ced7508e5c231b1afa5c05713eaf87610499ee23f471a",
                    ))
                    .dispatch();

                assert_eq!(response.status(), Status::Ok);
            },
        );

        let mut path = temp_dir.path().to_path_buf();
        path.push("file.temp");
        // Check file exists
        assert!(std::fs::exists(&path).expect("Exists"));

        // Check correct content
        let content = std::fs::read_to_string(path).expect("Valid file");
        assert_eq!(content, "hi\n");
    }
}
