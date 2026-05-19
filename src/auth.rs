use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use lz4_flex::decompress_size_prepended;

use crate::structs::{CasdoorClaims, CasdoorUser};

// =============================================================================
//  AUTH HELPER
// =============================================================================

#[derive(Clone)]
pub struct AuthHelper {
    decoding_key: DecodingKey,
    validation: Validation,
    group_prefix: String,
}

impl AuthHelper {
    pub fn new(certificate_pem: &str, group_prefix: String) -> Result<Self, String> {
        let decoding_key = DecodingKey::from_rsa_pem(certificate_pem.as_bytes())
            .map_err(|e| format!("Invalid RSA public key: {}", e))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 60;
        validation.validate_aud = false;

        Ok(Self {
            decoding_key,
            validation,
            group_prefix,
        })
    }

    /// Detects the wire format and extracts the raw JWT string.
    ///
    /// Wire format protocol:
    /// - Byte 0 == 0x01: Compressed (strip prefix, B64 decode, LZ4 decompress)
    /// - Byte 0 == 'e' (starts with "eyJ"): Raw JWT
    fn extract_jwt(token: &str) -> Result<String, String> {
        let bytes = token.as_bytes();
        if bytes.is_empty() {
            return Err("Empty token".into());
        }

        match bytes[0] {
            0x01 => {
                // Compressed format: strip prefix, base64 decode, LZ4 decompress
                let encoded = &token[1..];
                let compressed = BASE64
                    .decode(encoded)
                    .map_err(|e| format!("Base64 decode failed: {}", e))?;
                let decompressed = decompress_size_prepended(&compressed)
                    .map_err(|e| format!("LZ4 decompression failed: {}", e))?;
                String::from_utf8(decompressed)
                    .map_err(|e| format!("Decompressed data is not valid UTF-8: {}", e))
            }
            b'e' => {
                // Raw JWT (starts with "eyJ...")
                Ok(token.to_string())
            }
            other => Err(format!(
                "Unknown token format: first byte is 0x{:02x}, expected 0x01 (compressed) or 'e' (raw JWT)",
                other
            )),
        }
    }

    /// Validates the token (raw JWT or compressed) and returns a CasdoorUser
    /// context object with pre-calculated summaries.
    pub fn parse_user(&self, token: &str) -> Result<CasdoorUser, String> {
        let jwt = Self::extract_jwt(token)?;
        let mut claims = decode::<CasdoorClaims>(&jwt, &self.decoding_key, &self.validation)
            .map(|td| td.claims)
            .map_err(|e| format!("JWT validation failed: {}", e))?;

        // claims.groups
        let prefix_with_sep = format!("{}_", self.group_prefix);
        for g in claims.groups.iter_mut() {
            *g = g
                .strip_prefix(&prefix_with_sep)
                .map(|v| v.to_string())
                .unwrap_or(g.to_string());
        }

        CasdoorUser::new(claims, &self.group_prefix)
    }

    pub fn is_valid(&self, token: &str) -> bool {
        self.parse_user(token).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use lz4_flex::compress_prepend_size;

    #[test]
    fn test_detect_raw_jwt_format() {
        let token = "eyJhbGciOiJSUzI1NiJ9.payload.signature";
        let result = AuthHelper::extract_jwt(token);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), token);
    }

    #[test]
    fn test_detect_unknown_format() {
        let token = "xyz-not-a-valid-format";
        let result = AuthHelper::extract_jwt(token);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown token format"));
    }

    #[test]
    fn test_compressed_format_roundtrip() {
        let original_jwt = "eyJhbGciOiJSUzI1NiJ9.test-payload.test-signature";
        let compressed = compress_prepend_size(original_jwt.as_bytes());
        let encoded = STANDARD.encode(&compressed);
        let token = format!("\x01{}", encoded);

        let extracted = AuthHelper::extract_jwt(&token).unwrap();
        assert_eq!(extracted, original_jwt);
    }

    #[test]
    fn test_empty_token_errors() {
        let result = AuthHelper::extract_jwt("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Empty token"));
    }
}
