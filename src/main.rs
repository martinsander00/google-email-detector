use serde::{Deserialize, Serialize}; // serializing and deserializing data structures; json
use std::fs; // read and write to documents
use std::collections::HashMap; // hash map implementation
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, TokenUrl, basic::BasicClient, TokenResponse, Scope}; // facilitates oauth authentication for secure access to APIs
use warp::Filter; // creates web server routes and handles async requests
use reqwest::StatusCode; // allows handling and checking HTTP status codes in a more readable and error-resistant way
use anyhow::Result; // simplified error handling, alias for Result<T, anyhow::Error
use core::convert::Infallible; // type signatures where a function is guaranteed not to return an error
use std::net::TcpListener; // used to listen for TCP network connections. It binds to a socket address and listens for incoming connections, which are then handled as TCP streams
use tokio::time::{sleep, Duration}; // used to delay operations in asynchronous applications
use base64; // encoding and decoding data as base64


////////////////////////////////////////////


const CREDENTIALS_PATH: &str = "credentials.json";


////////////////////////////////////////////


#[derive(Deserialize, Serialize, Debug)]
struct CredentialsConfig {
    installed: Credentials,
}

#[derive(Deserialize, Serialize, Debug)]
struct Credentials {
    client_id: String,
    project_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_secret: String,
    redirect_uris: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct TokenInfo {
    access_token: String,
    refresh_token: String,
}


////////////////////////////////////////////


// Function to read and parse the OAuth 2.0 credentials
fn read_credentials(file_path: &str) -> Result<Credentials> {
    let data = fs::read_to_string(file_path)?;
    let config: CredentialsConfig = serde_json::from_str(&data)?; // deserialize a JSON string into a Rust data structure
    Ok(config.installed)
}

// Function to read tokens from a file
fn read_tokens(file_path: &str) -> Result<TokenInfo> {
    let data = fs::read_to_string(file_path)?;
    let tokens: TokenInfo = serde_json::from_str(&data)?;
    Ok(tokens)
}

// Function to save tokens to a file
fn save_tokens(access_token: &str, refresh_token: &str) -> Result<()> {
    let token_info = TokenInfo {
        access_token: access_token.to_string(),
        refresh_token: refresh_token.to_string(),
    };
    let data = serde_json::to_string(&token_info)?; // serialize a Rust data structure into a JSON string
    fs::write("tokens.json", data)?;
    Ok(())
}


// Our app after receiving the auth code it's like saying, google the user authorized us,
// now give me the tokens to access this user's resources
async fn handle_request(params: HashMap<String, String>, client: BasicClient) -> Result<impl warp::Reply, Infallible> {
    println!("Received a callback with these parameters:");
    for (key, value) in params.iter() {
        println!("{}: {}", key, value);
    }

    if let Some(code) = params.get("code") {
        println!("Authorization code: {}", code);
        match exchange_code_for_token(&client, code.to_string()).await {
            Ok((access_token, refresh_token)) => {
                // Save both tokens; refresh token might not always be present, so a check is needed
                if let Err(e) = save_tokens(&access_token, refresh_token.as_deref().unwrap_or("")) {
                    eprintln!("Failed to save tokens: {}", e);
                }
            },
            Err(e) => eprintln!("Failed to exchange token: {}", e),
        }
    } else {
        println!("Authorization code not received");
    }

    Ok(warp::reply::with_status("Callback handled successfully.", StatusCode::OK))
}

// BasicClient is a struct provided by the oauth2 crate in Rust. It represents a client for the
// OAuth 2.0 protocol that can be used to perform various OAuth 2.0 flows, including exchanging
// authorization codes for tokens, refreshing tokens
async fn exchange_code_for_token(client: &BasicClient, code: String) -> Result<(String, Option<String>)> {
    // asynchronous request to Google's token endpoint to exchange the authorization code for tokens
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(oauth2::reqwest::async_http_client)
        .await?;

    let access_token = token_response.access_token().secret().clone();
    let refresh_token = token_response.refresh_token().map(|rt| rt.secret().clone());

    println!("Access token: {}", access_token);
    if let Some(ref_token) = &refresh_token {
        println!("Refresh token: {}", ref_token);
    }

    Ok((access_token, refresh_token))
}

async fn fetch_emails(http_client: &reqwest::Client, access_token: &str) -> Result<Vec<serde_json::Value>, reqwest::Error> {
    let url = "https://www.googleapis.com/gmail/v1/users/me/messages?q=is:unread";
    let response = http_client
        .get(url) // initiates a GET request to the specified URL
        .bearer_auth(access_token) // sets the Bearer token (used for token-based auth) for the Authorization header
        .send() // sends the built request to the server
        .await? // wait for send to complete
        .json::<serde_json::Value>() // deserialize the JSON response body into a serde_json::Value
        .await?; // wait for json to complete

    // response looks like this:
    // {
    //   "messages": [
    //     {
    //       "id": "12345",
    //       "threadId": "67890"
    //     },
    //     {
    //       "id": "54321",
    //       "threadId": "09876"
    //     }
    //   ],
    //   "resultSizeEstimate": 2
    // }

    if let Some(messages) = response["messages"].as_array() {
        // iterates over the array of messages, clones each element,
        // and collects them into a Vec<serde_json::Value>.
        Ok(messages.iter().cloned().collect())
    } else {
        Ok(vec![])
    }
}

async fn get_email_details(http_client: &reqwest::Client, access_token: &str, email_id: &str) -> Result<String, reqwest::Error> {
    let url = format!("https://www.googleapis.com/gmail/v1/users/me/messages/{}", email_id);
    let response = http_client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    // FOR NOW, printing the whole email object here
    Ok(response.to_string())
}

// Helper to decode base64 URL encoded strings
fn decode_base64(input: &str) -> Result<String, base64::DecodeError> {
    base64::decode_config(input, base64::URL_SAFE) // decode from base64 to binary (bytes)
        .map(|bytes| String::from_utf8(bytes) // takes the bytes (result of decode_config) and converts these into a STring
        .unwrap_or_else(|_| String::new())) // This method is called on the Result returned by String::from_utf8.
        // If the result is Ok, it returns the String. If the result is Err, the closure |_| String::new()
        // is called, which ignores the error and returns a new, empty String instead
}



// payload JSON may look something like this at the start:
// {
//   "id": "email_unique_id12345",
//   "threadId": "thread_unique_id12345",
//   "labelIds": ["INBOX", "UNREAD"],
//   "snippet": "This is a brief snippet of the email content...",
//   "historyId": "987654",
//   "internalDate": "1625097612000",
//   "payload": {
//     "mimeType": "multipart/alternative",
//     "filename": "",
//     "headers": [
//       {
//         "name": "From",
//         "value": "sender@example.com"
//       },
//       {
//         "name": "To",
//         "value": "recipient@example.com"
//       },
//       {
//         "name": "Subject",
//         "value": "Your Subject Here"
//       },
//       {
//         "name": "Date",
//         "value": "Thu, 1 Jul 2021 12:00:00 -0400"
//       }
//     ],
//     "parts": [
//       {
//         "mimeType": "text/plain",
//         "body": {
//           "data": "SGVsbG8sIHRoaXMgaXMgdGhlIHBsYWluIHRleHQgdmVyc2lvbiBvZiB0aGUgZW1haWwu",
//           "size": 200
//         }
//       },
//       {
//         "mimeType": "text/html",
//         "body": {
//           "data": "PGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsOyI+SGVsbG8sIHRoaXMgaXMgdGhlIDxiPkhUTUw8L2I==",
//           "size": 300
//         }
//       }
//     ]
//   },
//   "sizeEstimate": 500
// }

// Function to parse the payload and extract desired information, input is JSON format
fn parse_email_details(payload: &serde_json::Value) -> (String, String, String, String, Vec<String>, Vec<String>) {
    let headers = payload["headers"].as_array().cloned().unwrap_or_else(Vec::new);
    // Use cloning when we need to own the data, potentially modify it, or when passing data across thread
    // boundaries in a multithreaded context

    // Parse it like this
    // Some(&vec![
    //     serde_json::json!({"name": "From", "value": "sender@example.com"}),
    //     serde_json::json!({"name": "To", "value": "recipient@example.com"}),
    //     serde_json::json!({"name": "Subject", "value": "Your Subject Here"}),
    //     serde_json::json!({"name": "Date", "value": "Thu, 1 Jul 2021 12:00:00 -0400"})
    // ])

    let subject = headers.iter()
        .find(|&h| h["name"] == "Subject")
        .and_then(|h| h["value"].as_str()) // and_then: method used to chain computations that might return None, h["value"].as_str() attempts to get the &str representation of the "value" field from the header. If successful, it returns Some(&str); otherwise, it returns None
        .unwrap_or("") // If the result from and_then is None, unwrap_or returns the provided default value, which is an empty string ""
        .to_string(); // converts the final &str (whether from Some(&str) or the default "") to an owned String
    let sender = headers.iter()
        .find(|&h| h["name"] == "From")
        .and_then(|h| h["value"].as_str())
        .unwrap_or("")
        .to_string();

    let parts = payload["parts"].as_array().cloned().unwrap_or_else(Vec::new);
    let mut body_text = String::new();
    // Let's assume you will use body_html later
    let mut body_html = String::new();
    let mut attachments = Vec::new();
    let mut links = Vec::new();

    for part in parts {
        match part["mimeType"].as_str() {
            Some("text/plain") => {
                // Check if the "data" field of the "body" can be interpreted as a string
                if let Some(body_data) = part["body"]["data"].as_str() {
                    if let Ok(decoded) = decode_base64(body_data) {
                        body_text = decoded;
                    }
                }
            },
            Some("text/html") => {
                if let Some(body_data) = part["body"]["data"].as_str() {
                    if let Ok(decoded) = decode_base64(body_data) {
                        body_html = decoded;
                        // Extract and store all links from the HTML body
                        links.extend(body_html.matches("href=\"http") // matches returns an iterator over all the substrings that match the given pattern "href=\"http"
                            .map(|m| m.trim_start_matches("href=\"").to_string()));
                        // |m|: This defines the closure, where m represents each match found by the matches method
                        // m.trim_start_matches("href=\""): For each match m, this method removes the href="
                        // prefix from the beginning of the match
                        // .extend(...): The extend method is called on links. This method takes an iterator
                        // and appends each element of the iterator to the links vector
                    }
                }
            },
            _ => {
                // If the part does not match text/plain or text/html, it handles it as an attachment
                if part["filename"].as_str().unwrap_or("").is_empty() {
                    attachments.push(part["filename"].as_str().unwrap_or("").to_string());
                    // If part has a filename, add it to attachments vector
                }
            },
        }
    }

    (subject, sender, body_text, body_html, links, attachments)
}


///----------------ANALYZED TIL HERE------------------///

async fn request_authentication(client: &BasicClient) -> Result<()> {
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("https://www.googleapis.com/auth/gmail.readonly".to_string()))
        .add_scope(Scope::new("https://www.googleapis.com/auth/cloud-platform.read-only".to_string()))
        .url();

    println!("Please authenticate by visiting the following URL: {}", auth_url);

    if webbrowser::open(auth_url.as_str()).is_err() {
        println!("Failed to open web browser automatically. Please open the URL manually.");
    }

    Ok(())
}

async fn serve(client: BasicClient) {
    let client_filter = warp::any().map(move || client.clone());
    let route = warp::path("callback")
        .and(warp::query::<HashMap<String, String>>())
        .and(client_filter)
        .and_then(handle_request);

    warp::serve(route).run(([127, 0, 0, 1], 8080)).await;
}

async fn validate_token(access_token: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://www.googleapis.com/oauth2/v1/tokeninfo")
        .query(&[("access_token", access_token)])
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Token validation failed"))
    }
}

async fn application_loop(http_client: &reqwest::Client) {
    loop {
        // Read the access token from tokens.json file again in case they become invalid during fetching loop
        let token_info = match read_tokens("tokens.json") {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Failed to read tokens: {}", e);
                sleep(Duration::from_secs(60)).await; // Wait before trying again
                continue;
            }
        };

        match fetch_emails(&http_client, &token_info.access_token).await {
            Ok(emails) => {
                println!("Fetched {} emails", emails.len());
                for email in emails {
                    println!("Email ID: {}", email["id"]);
                    match get_email_details(&http_client, &token_info.access_token, email["id"].as_str().unwrap()).await {
                        Ok(details) => {
                            let details_json: serde_json::Value = serde_json::from_str(&details).unwrap();
                            let (subject, sender, body_text, body_html, links, attachments) = parse_email_details(&details_json["payload"]);
                            println!("Subject: {}", subject);
                            println!("Sender: {}", sender);
                            println!("Body (Text): {}", body_text);
                            println!("Body (HTML): {}", body_html);
                            println!("Links: {:?}", links);
                            println!("Attachments: {:?}", attachments);
                        },
                        Err(e) => eprintln!("Failed to fetch email details: {}", e),
                    }
                }
            },
            Err(e) => {
                eprintln!("Error fetching emails: {}", e);
                // If token is expired or invalid, refresh it
                if e.to_string().contains("401") { // Unauthorized, token may be expired
                    // Attempt to refresh the access token here
                }
            },
        }
        sleep(Duration::from_secs(5)).await; // Adjust frequency as needed
    }
}


/////////////////////////////////////////////////////


#[tokio::main]
async fn main() -> Result<()> {
    if TcpListener::bind("127.0.0.1:8080").is_err() {
        eprintln!("Port 8080 is already in use.");
        std::process::exit(1);
    }

    let creds = read_credentials(CREDENTIALS_PATH)?;
    let oauth_client = BasicClient::new(
        ClientId::new(creds.client_id),
        Some(ClientSecret::new(creds.client_secret)),
        AuthUrl::new(creds.auth_uri)?,
        Some(TokenUrl::new(creds.token_uri)?)
    )
    .set_redirect_uri(RedirectUrl::new(creds.redirect_uris[0].clone())?);

    // Attempt to read the existing tokens
    let token_info = read_tokens("tokens.json").ok();

    // Check if the existing access token is valid
    if let Some(info) = token_info {
        if validate_token(&info.access_token).await.is_ok() {
            println!("Existing token is valid. No need to re-authenticate.");
        } else {
            println!("Token validation failed. Please re-authenticate.");
            request_authentication(&oauth_client).await?;
        }
    } else {
        println!("No existing token found. Please authenticate.");
        request_authentication(&oauth_client).await?;
    }

    // Start the web server to handle the OAuth callback
    tokio::spawn(async move {
        serve(oauth_client).await;
    });

    // HTTP client to interact with APIs after auth
    let http_client = reqwest::Client::new();

    // Main application loop for fetching emails
    application_loop(&http_client).await;

    Ok(())
}