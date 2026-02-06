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
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IdpClaims {
    pub sub: String,
    pub exp: i64,
    pub iss: Option<String>,
    pub is_admin: bool,
    pub roles: Option<Vec<IdpRoleData>>,
    pub groups: Option<Vec<String>>,
    pub permissions: Option<Vec<IdpPermissionData>>, 
    pub properties: Option<HashMap<String, String>>,
}

// -----------------------------------------------------------------------------
//  Output Structures
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

#[derive(Clone)]
pub struct AuthHelper {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl AuthHelper {
    pub fn new(public_key_pem: &str) -> Result<Self, String> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .map_err(|e| format!("Invalid Public Key: {}", e))?;
        
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 60;
        
        Ok(Self { decoding_key, validation })
    }

    pub fn is_valid(&self, jwt: &str) -> Result<IdpClaims, String> {
        let token_data = decode::<IdpClaims>(jwt, &self.decoding_key, &self.validation)
            .map_err(|e| format!("JWT Validation Failed: {}", e))?;
        Ok(token_data.claims)
    }

    pub fn get_org_authorisations(&self, jwt: &str) -> Result<Vec<OrgAuthSummary>, String> {
        let claims = self.is_valid(jwt)?;
        
        let groups = claims.groups.unwrap_or_default();
        let all_roles = claims.roles.unwrap_or_default();
        let all_perms = claims.permissions.unwrap_or_default();

        let mut org_summaries = Vec::new();

        for (i, group) in groups.iter().enumerate() {
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
                    description: "Permission details".to_string(),
                })
                .collect();

            org_summaries.push(OrgAuthSummary {
                org_id: group.clone(),
                org_name: group.split('/').last().unwrap_or(group).to_string(),
                is_default: i == 0,
                roles: org_roles,
                permissions: org_perms,
            });
        }

        Ok(org_summaries)
    }

    // --- NEW LOGIC START ---

    /// Helper to resolve target Org ID based on input or claims
    fn resolve_target_org(&self, claims: &IdpClaims, org_id: Option<&str>) -> Result<String, String> {
        if let Some(id) = org_id {
            return Ok(id.to_string());
        }

        let groups = claims.groups.as_deref().unwrap_or(&[]);
        match groups.len() {
            1 => Ok(groups[0].clone()),
            0 => Err("No Org ID provided and no groups found in token.".to_string()),
            n => Err(format!("Ambiguous Org context: Token contains {} groups; explicit Org ID required.", n)),
        }
    }

    /// `has_role`: Now returns Result to handle ambiguity errors
    pub fn has_role(&self, jwt: &str, org_id: Option<&str>, role_name: &str) -> Result<bool, String> {
        let claims = self.is_valid(jwt)?;
        let target_org = self.resolve_target_org(&claims, org_id)?;

        if let Some(roles) = &claims.roles {
            Ok(roles.iter().any(|r| r.name == role_name && target_org.contains(&r.owner)))
        } else {
            Ok(false)
        }
    }

    /// `has_permission`: Now returns Result to handle ambiguity errors
    pub fn has_permission(&self, jwt: &str, org_id: Option<&str>, perm_name: &str) -> Result<bool, String> {
        let claims = self.is_valid(jwt)?;
        let target_org = self.resolve_target_org(&claims, org_id)?;

        if let Some(perms) = &claims.permissions {
            Ok(perms.iter().any(|p| p.name == perm_name && target_org.contains(&p.owner)))
        } else {
            Ok(false)
        }
    }
    // --- NEW LOGIC END ---
}

// =============================================================================
//  PYTHON BINDINGS
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
        serde_json::to_string(&auths)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    // Updated to accept Optional org_id and return Result (throws exception in Python on error)
    fn has_role(&self, jwt: String, org_id: Option<String>, role_name: String) -> PyResult<bool> {
        self.inner.has_role(&jwt, org_id.as_deref(), &role_name)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    fn has_permission(&self, jwt: String, org_id: Option<String>, perm_name: String) -> PyResult<bool> {
        self.inner.has_permission(&jwt, org_id.as_deref(), &perm_name)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn nf_auth_helper(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIdpAuthHelper>()?;
    Ok(())
}

// =============================================================================
//  WASM / NPM BINDINGS
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

    #[wasm_bindgen(js_name = getOrgAuthorisations)]
    pub fn get_org_authorisations(&self, jwt: &str) -> Result<JsValue, JsError> {
        let auths = self.inner.get_org_authorisations(jwt)
            .map_err(|e| JsError::new(&e))?;
        serde_wasm_bindgen::to_value(&auths).map_err(Into::into)
    }

    // Updated to accept Optional org_id (null/undefined in JS) and return Result (throws Error in JS)
    #[wasm_bindgen(js_name = hasRole)]
    pub fn has_role(&self, jwt: &str, org_id: Option<String>, role_name: &str) -> Result<bool, JsError> {
        self.inner.has_role(jwt, org_id.as_deref(), role_name)
            .map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = hasPermission)]
    pub fn has_permission(&self, jwt: &str, org_id: Option<String>, perm_name: &str) -> Result<bool, JsError> {
        self.inner.has_permission(jwt, org_id.as_deref(), perm_name)
            .map_err(|e| JsError::new(&e))
    }
}
