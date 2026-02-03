use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
//  CORE RUST LOGIC (Platform Agnostic)
// =============================================================================

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IdpRoleData {
    pub owner: String, // Maps to Org/Tenant
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IdpPermissionData {
    pub owner: String,
    pub name: String,
    // Add other fields as needed based on your IDP's permission structure
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IdpClaims {
    pub sub: String,
    pub exp: i64,
    pub iss: Option<String>,
    
    // Auth & Status
    pub is_admin: bool,

    // IDP Specific
    pub roles: Option<Vec<IdpRoleData>>,
    pub groups: Option<Vec<String>>,
    pub permissions: Option<Vec<IdpPermissionData>>, 
    pub properties: Option<HashMap<String, String>>,
}

// -----------------------------------------------------------------------------
//  Output Structures for `get_org_authorisations`
// -----------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrgAuthSummary {
    pub org_id: String,
    pub org_name: String,
    pub is_default: bool,
    pub roles: Vec<RoleSummary>,
    pub permissions: Vec<PermissionSummary>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoleSummary {
    pub name: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PermissionSummary {
    pub name: String,
    pub description: String,
}

// =============================================================================
//  THE AUTH HELPER (The Main Engine)
// =============================================================================

/// The central utility that holds the IDP's public key for signature verification.
#[derive(Clone)]
pub struct AuthHelper {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl AuthHelper {
    /// Initialize with the IDP's Public Certificate (PEM format)
    pub fn new(public_key_pem: &str) -> Result<Self, String> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .map_err(|e| format!("Invalid Public Key: {}", e))?;
        
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 60; // 60 seconds of clock skew allowed
        
        Ok(Self { decoding_key, validation })
    }

    /// `is_valid (JWT)`: Parses, verifies signature, and checks expiry.
    pub fn is_valid(&self, jwt: &str) -> Result<IdpClaims, String> {
        let token_data = decode::<IdpClaims>(jwt, &self.decoding_key, &self.validation)
            .map_err(|e| format!("JWT Validation Failed: {}", e))?;
        
        Ok(token_data.claims)
    }

    /// `get_org_authorisations (JWT)`: Returns grouped lists of Orgs, Roles, and Permissions.
    pub fn get_org_authorisations(&self, jwt: &str) -> Result<Vec<OrgAuthSummary>, String> {
        let claims = self.is_valid(jwt)?;
        
        // Map groups to Orgs. Assuming group format is "owner/org_name"
        let groups = claims.groups.unwrap_or_default();
        let all_roles = claims.roles.unwrap_or_default();
        let all_perms = claims.permissions.unwrap_or_default();

        let mut org_summaries = Vec::new();

        for (i, group) in groups.iter().enumerate() {
            // Filter roles and perms for this specific group/org
            // (Assuming `owner` field in roles matches the group or org ID)
            let org_roles: Vec<RoleSummary> = all_roles.iter()
                .filter(|r| group.contains(&r.owner))
                .map(|r| RoleSummary {
                    name: r.name.clone(),
                    description: r.description.clone().unwrap_or_default(),
                })
                .collect();

            let org_perms: Vec<PermissionSummary> = all_perms.iter()
                .filter(|p| group.contains(&p.owner))
                .map(|p| PermissionSummary {
                    name: p.name.clone(),
                    description: "Permission details".to_string(), // Placeholder
                })
                .collect();

            org_summaries.push(OrgAuthSummary {
                org_id: group.clone(),
                org_name: group.split('/').last().unwrap_or(group).to_string(),
                is_default: i == 0, // Assume first group is default
                roles: org_roles,
                permissions: org_perms,
            });
        }

        Ok(org_summaries)
    }

    /// `has_role (JWT, OrgID, Role)`: Implicitly validates JWT and checks role.
    pub fn has_role(&self, jwt: &str, org_id: &str, role_name: &str) -> bool {
        match self.is_valid(jwt) {
            Ok(claims) => {
                if let Some(roles) = claims.roles {
                    roles.iter().any(|r| r.name == role_name && org_id.contains(&r.owner))
                } else {
                    false
                }
            },
            Err(_) => false, // Invalid JWT means no roles
        }
    }

    /// `has_permission (JWT, OrgID, Perm)`: Implicitly validates JWT and checks perm.
    pub fn has_permission(&self, jwt: &str, org_id: &str, perm_name: &str) -> bool {
        match self.is_valid(jwt) {
            Ok(claims) => {
                if let Some(perms) = claims.permissions {
                    perms.iter().any(|p| p.name == perm_name && org_id.contains(&p.owner))
                } else {
                    false
                }
            },
            Err(_) => false,
        }
    }
}

// =============================================================================
//  PYTHON BINDINGS (#[cfg(feature = "python")])
// =============================================================================

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pyclass(name = "IdpAuthHelper")]
pub struct PyIdpAuthHelper {
    inner: AuthHelper,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyIdpAuthHelper {
    #[new]
    fn new(public_key_pem: String) -> PyResult<Self> {
        let inner = AuthHelper::new(&public_key_pem)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        Ok(PyIdpAuthHelper { inner })
    }

    fn is_valid(&self, jwt: String) -> bool {
        self.inner.is_valid(&jwt).is_ok()
    }

    fn get_org_authorisations(&self, jwt: String) -> PyResult<String> {
        let auths = self.inner.get_org_authorisations(&jwt)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        // Return as JSON string to Python for easy dictionary conversion
        serde_json::to_string(&auths)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn has_role(&self, jwt: String, org_id: String, role_name: String) -> bool {
        self.inner.has_role(&jwt, &org_id, &role_name)
    }

    fn has_permission(&self, jwt: String, org_id: String, perm_name: String) -> bool {
        self.inner.has_permission(&jwt, &org_id, &perm_name)
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn nf_auth_helper(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIdpAuthHelper>()?;
    Ok(())
}

// =============================================================================
//  WASM / NPM BINDINGS (#[cfg(feature = "wasm")])
// =============================================================================

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = IdpAuthHelper)]
pub struct WasmIdpAuthHelper {
    inner: AuthHelper,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_class = IdpAuthHelper)]
impl WasmIdpAuthHelper {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key_pem: &str) -> Result<WasmIdpAuthHelper, JsError> {
        let inner = AuthHelper::new(public_key_pem)
            .map_err(|e| JsError::new(&e))?;
        Ok(WasmIdpAuthHelper { inner })
    }

    #[wasm_bindgen(js_name = isValid)]
    pub fn is_valid(&self, jwt: &str) -> bool {
        self.inner.is_valid(jwt).is_ok()
    }

    #[wasm_bindgen(js_name = hasRole)]
    pub fn has_role(&self, jwt: &str, org_id: &str, role_name: &str) -> bool {
        self.inner.has_role(jwt, org_id, role_name)
    }

    #[wasm_bindgen(js_name = hasPermission)]
    pub fn has_permission(&self, jwt: &str, org_id: &str, perm_name: &str) -> bool {
        self.inner.has_permission(jwt, org_id, perm_name)
    }

    #[wasm_bindgen(js_name = getOrgAuthorisations)]
    pub fn get_org_authorisations(&self, jwt: &str) -> Result<JsValue, JsError> {
        let auths = self.inner.get_org_authorisations(jwt)
            .map_err(|e| JsError::new(&e))?;
        serde_wasm_bindgen::to_value(&auths).map_err(Into::into)
    }
}
