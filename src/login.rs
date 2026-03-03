use serde::{Deserialize, Serialize};

/// Request body for the Casdoor OAuth password grant.
#[derive(Serialize)]
pub struct LoginRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub username: String,
    pub password: String,
}

/// Response from the Casdoor OAuth token endpoint.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct LoginResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

/// Authenticate with the Casdoor IDP using the OAuth password grant.
///
/// # Arguments
/// * `idp_base_url` - Base URL of the IDP (e.g., "https://idp.nuflights.com")
/// * `client_id` - OAuth client ID
/// * `client_secret` - OAuth client secret
/// * `username` - User's username
/// * `password` - User's password
pub fn login(
    idp_base_url: &str,
    client_id: &str,
    client_secret: &str,
    username: &str,
    password: &str,
) -> Result<LoginResponse, String> {
    let url = format!(
        "{}/api/login/oauth/access_token",
        idp_base_url.trim_end_matches('/')
    );

    let body = LoginRequest {
        grant_type: "password".to_string(),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        username: username.to_string(),
        password: password.to_string(),
    };

    let response = reqwest::blocking::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .map_err(|e| format!("Login request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().unwrap_or_default();
        return Err(format!("Login failed with status {}: {}", status, body_text));
    }

    response
        .json::<LoginResponse>()
        .map_err(|e| format!("Failed to parse login response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_request_serialization() {
        let req = LoginRequest {
            grant_type: "password".to_string(),
            client_id: "test_id".to_string(),
            client_secret: "test_secret".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["grant_type"], "password");
        assert_eq!(json["client_id"], "test_id");
        assert_eq!(json["client_secret"], "test_secret");
        assert_eq!(json["username"], "user");
        assert_eq!(json["password"], "pass");
    }

    #[test]
    fn test_login_response_deserialization() {
        let json = r#"{
            "access_token": "eyJ...",
            "refresh_token": "eyR...",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#;
        let resp: LoginResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "eyJ...");
        assert_eq!(resp.refresh_token.as_deref(), Some("eyR..."));
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.expires_in, Some(3600));
    }

    #[test]
    fn test_login_response_minimal() {
        let json = r#"{"access_token": "token123"}"#;
        let resp: LoginResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "token123");
        assert!(resp.refresh_token.is_none());
        assert!(resp.token_type.is_none());
        assert!(resp.expires_in.is_none());
    }
}
