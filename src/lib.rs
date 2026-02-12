use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
//  CASDOOR JWT STRUCTS
// =============================================================================

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorRole {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub created_time: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    #[serde(default)]
    pub users: Option<serde_json::Value>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub domains: Option<Vec<String>>,
    #[serde(default)]
    pub is_enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorPermission {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub created_time: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub users: Option<serde_json::Value>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub domains: Option<Vec<String>>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub adapter: Option<String>,
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub resources: Option<Vec<String>>,
    #[serde(default)]
    pub actions: Option<Vec<String>>,
    #[serde(default)]
    pub effect: Option<String>,
    #[serde(default)]
    pub is_enabled: bool,
    #[serde(default)]
    pub submitter: Option<String>,
    #[serde(default)]
    pub approver: Option<String>,
    #[serde(default)]
    pub approve_time: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorClaims {
    // --- JWT Standard Claims ---
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    #[serde(default)]
    pub exp: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub jti: Option<String>,

    // --- Casdoor Token metadata ---
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,

    // --- User identity ---
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, rename = "type")]
    pub user_type: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub affiliation: Option<String>,
    #[serde(default)]
    pub signup_application: Option<String>,
    #[serde(default)]
    pub score: Option<i32>,
    #[serde(default)]
    pub ranking: Option<i32>,

    // --- Admin flags ---
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub is_global_admin: bool,
    #[serde(default)]
    pub is_forbidden: bool,
    #[serde(default)]
    pub is_deleted: bool,

    // --- RBAC ---
    #[serde(default)]
    pub roles: Option<Vec<CasdoorRole>>,
    #[serde(default)]
    pub permissions: Option<Vec<CasdoorPermission>>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,

    #[serde(default)]
    pub properties: Option<HashMap<String, String>>,
}

// =============================================================================
//  OUTPUT STRUCTURES
// =============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupAuthSummary {
    pub org_name: String,
    pub org_short_code: String,
    pub is_direct_member: bool,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

// =============================================================================
//  CASDOOR USER (Context Object)
// =============================================================================

/// This struct holds the parsed state. It is returned by AuthHelper::validate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CasdoorUser {
    pub claims: CasdoorClaims,
    pub summaries: Vec<GroupAuthSummary>,
}

impl CasdoorUser {
    pub fn new(claims: CasdoorClaims) -> Self {
        let summaries = Self::compute_summaries(&claims);
        Self { claims, summaries }
    }

    /// Internal logic to pre-calculate the authentication summaries
    fn compute_summaries(claims: &CasdoorClaims) -> Vec<GroupAuthSummary> {
        let user_roles = claims.roles.as_deref().unwrap_or(&[]);
        let user_perms = claims.permissions.as_deref().unwrap_or(&[]);
        let direct_groups = claims.groups.as_deref().unwrap_or(&[]);

        // 1. Collect all unique groups
        let all_groups = AuthHelper::collect_all_groups(claims);

        let mut summaries = Vec::new();

        for group_fq in &all_groups {
            let group_name = group_fq
                .split_once('/')
                .map(|(_, n)| n.to_string())
                .unwrap_or_else(|| group_fq.clone());

            let is_direct = direct_groups.contains(group_fq);

            // 2. Roles scoped to this group
            let role_names: Vec<String> = AuthHelper::roles_for_group(user_roles, group_fq)
                .iter()
                .map(|r| r.name.clone())
                .collect();

            // 3. Permissions scoped to this group (via role ref)
            let perm_names: Vec<String> = user_perms
                .iter()
                .filter(|p| {
                    p.is_enabled
                        && p.roles.as_ref().is_some_and(|perm_roles| {
                            perm_roles.iter().any(|role_ref| {
                                AuthHelper::user_has_role_ref_for_group(
                                    user_roles, role_ref, group_fq,
                                )
                            })
                        })
                })
                .map(|p| p.name.clone())
                .collect();

            summaries.push(GroupAuthSummary {
                org_name: group_fq.clone(),
                org_short_code: group_name,
                is_direct_member: is_direct,
                roles: role_names,
                permissions: perm_names,
            });
        }
        summaries
    }

    /// Check if user belongs to a group (direct or via role)
    pub fn has_group(&self, group_name: &str) -> bool {
        let group_fq = AuthHelper::qualify_group(&self.claims, group_name);
        self.summaries.iter().any(|s| s.org_name == group_fq)
    }

    /// Check if user has role. If group is None, infer default group (if only 1 exists).
    pub fn has_role(&self, role_name: &str, group_name: Option<&str>) -> Result<bool, String> {
        let group_fq = AuthHelper::resolve_group_from_summaries(
            &self.summaries,
            &self.claims.owner,
            group_name,
        )?;

        if let Some(summary) = self.summaries.iter().find(|s| s.org_name == group_fq) {
            Ok(summary.roles.contains(&role_name.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Check if user has permission. If group is None, infer default group (if only 1 exists).
    pub fn has_permission(
        &self,
        perm_name: &str,
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let group_fq = AuthHelper::resolve_group_from_summaries(
            &self.summaries,
            &self.claims.owner,
            group_name,
        )?;

        if let Some(summary) = self.summaries.iter().find(|s| s.org_name == group_fq) {
            Ok(summary.permissions.contains(&perm_name.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Check if user has ALL provided permissions (Exhaustive check).
    pub fn has_permissions(
        &self,
        perm_names: &[String],
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let group_fq = AuthHelper::resolve_group_from_summaries(
            &self.summaries,
            &self.claims.owner,
            group_name,
        )?;

        if let Some(summary) = self.summaries.iter().find(|s| s.org_name == group_fq) {
            // Check if all requested permissions exist in the summary
            let all_exist = perm_names.iter().all(|p| summary.permissions.contains(p));
            Ok(all_exist)
        } else {
            Ok(false)
        }
    }

    /// Check if user has ANY of the provided permissions (Iterative check).
    pub fn has_permissions_any(
        &self,
        perm_names: &[String],
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let group_fq = AuthHelper::resolve_group_from_summaries(
            &self.summaries,
            &self.claims.owner,
            group_name,
        )?;

        if let Some(summary) = self.summaries.iter().find(|s| s.org_name == group_fq) {
            // Check if any requested permission exists in the summary
            let any_exist = perm_names.iter().any(|p| summary.permissions.contains(p));
            Ok(any_exist)
        } else {
            Ok(false)
        }
    }

    pub fn is_admin(&self) -> bool {
        self.claims.is_admin
    }

    pub fn is_global_admin(&self) -> bool {
        self.claims.is_global_admin
    }

    pub fn get_org_count(&self) -> usize {
        self.summaries.len()
    }

    pub fn get_first_org_short_code(&self) -> Option<String> {
        self.summaries.first().map(|s| s.org_short_code.clone())
    }

    pub fn username(&self) -> String {
        self.claims.name.clone()
    }

    pub fn email(&self) -> Option<String> {
        self.claims.email.clone()
    }

    pub fn id(&self) -> Option<String> {
        self.claims.id.clone()
    }
}

// =============================================================================
//  AUTH HELPER
// =============================================================================

#[derive(Clone)]
pub struct AuthHelper {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl AuthHelper {
    pub fn new(certificate_pem: &str) -> Result<Self, String> {
        let decoding_key = DecodingKey::from_rsa_pem(certificate_pem.as_bytes())
            .map_err(|e| format!("Invalid Public Key: {}", e))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 60;
        validation.validate_aud = false;

        Ok(Self {
            decoding_key,
            validation,
        })
    }

    /// Validates the JWT and returns a context object with pre-calculated summaries.
    pub fn parse_user(&self, jwt: &str) -> Result<CasdoorUser, String> {
        let claims = decode::<CasdoorClaims>(jwt, &self.decoding_key, &self.validation)
            .map(|td| td.claims)
            .map_err(|e| format!("JWT Validation Failed: {}", e))?;

        Ok(CasdoorUser::new(claims))
    }

    pub fn is_valid(&self, jwt: &str) -> bool {
        self.parse_user(jwt).is_ok()
    }

    // =========================================================================
    //  STATIC HELPERS
    // =========================================================================

    fn qualify_group(claims: &CasdoorClaims, group_name: &str) -> String {
        if group_name.contains('/') {
            group_name.to_string()
        } else {
            format!("{}/{}", claims.owner, group_name)
        }
    }

    fn collect_all_groups(claims: &CasdoorClaims) -> Vec<String> {
        let user_roles = claims.roles.as_deref().unwrap_or(&[]);
        let direct_groups = claims.groups.as_deref().unwrap_or(&[]);

        let mut all: Vec<String> = Vec::new();
        let mut add = |g: &str| {
            if !g.is_empty() && !all.contains(&g.to_string()) {
                all.push(g.to_string());
            }
        };

        for g in direct_groups {
            add(g);
        }
        for role in user_roles {
            if let Some(ref gs) = role.groups {
                for g in gs {
                    add(g);
                }
            }
        }
        all
    }

    fn resolve_group_from_summaries(
        summaries: &[GroupAuthSummary],
        owner: &str,
        group_name: Option<&str>,
    ) -> Result<String, String> {
        if let Some(name) = group_name {
            if name.contains('/') {
                return Ok(name.to_string());
            } else {
                return Ok(format!("{}/{}", owner, name));
            }
        }

        match summaries.len() {
            0 => Err("No group specified and user belongs to no groups.".to_string()),
            1 => Ok(summaries[0].org_name.clone()),
            n => {
                let names: Vec<&str> = summaries.iter().map(|s| s.org_name.as_str()).collect();
                Err(format!(
                    "No group specified and user belongs to {} groups: [{}]. Explicit group required.",
                    n,
                    names.join(", ")
                ))
            }
        }
    }

    fn roles_for_group<'a>(roles: &'a [CasdoorRole], group_fq: &str) -> Vec<&'a CasdoorRole> {
        roles
            .iter()
            .filter(|r| {
                r.is_enabled
                    && r.groups
                        .as_ref()
                        .is_some_and(|gs| gs.iter().any(|g| g == group_fq))
            })
            .collect()
    }

    fn user_has_role_ref_for_group(
        user_roles: &[CasdoorRole],
        role_ref: &str,
        group_fq: &str,
    ) -> bool {
        if let Some((role_owner, role_name)) = role_ref.split_once('/') {
            user_roles.iter().any(|r| {
                r.owner == role_owner
                    && r.name == role_name
                    && r.is_enabled
                    && r.groups
                        .as_ref()
                        .is_some_and(|gs| gs.iter().any(|g| g == group_fq))
            })
        } else {
            false
        }
    }
}

// =============================================================================
//  PYTHON BINDINGS
// =============================================================================

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pyclass(name = "CasdoorUser")]
pub struct PyCasdoorUser {
    inner: CasdoorUser,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyCasdoorUser {
    /// Returns the full list of group summaries as JSON
    fn get_auth_summary(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner.summaries)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Returns the raw JWT claims as JSON
    fn get_claims(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner.claims)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn has_group(&self, group_name: String) -> bool {
        self.inner.has_group(&group_name)
    }

    #[pyo3(signature = (role_name, group_name=None))]
    fn has_role(&self, role_name: String, group_name: Option<String>) -> PyResult<bool> {
        self.inner
            .has_role(&role_name, group_name.as_deref())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    #[pyo3(signature = (perm_name, group_name=None))]
    fn has_permission(&self, perm_name: String, group_name: Option<String>) -> PyResult<bool> {
        self.inner
            .has_permission(&perm_name, group_name.as_deref())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    /// Check if the user has ALL provided permissions (Exhaustive)
    /// accepts a list of strings from Python
    #[pyo3(signature = (perm_names, group_name=None))]
    fn has_permissions(
        &self,
        perm_names: Vec<String>,
        group_name: Option<String>,
    ) -> PyResult<bool> {
        self.inner
            .has_permissions(&perm_names, group_name.as_deref())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    /// Check if the user has ANY of the provided permissions (Iterative)
    /// accepts a list of strings from Python
    #[pyo3(signature = (perm_names, group_name=None))]
    fn has_permissions_any(
        &self,
        perm_names: Vec<String>,
        group_name: Option<String>,
    ) -> PyResult<bool> {
        self.inner
            .has_permissions_any(&perm_names, group_name.as_deref())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    #[getter]
    fn is_admin(&self) -> bool {
        self.inner.is_admin()
    }

    #[getter]
    fn is_global_admin(&self) -> bool {
        self.inner.is_global_admin()
    }

    pub fn get_org_count(&self) -> usize {
        self.inner.get_org_count()
    }

    pub fn get_first_org_short_code(&self) -> Option<String> {
        self.inner.get_first_org_short_code()
    }

    #[getter]
    pub fn username(&self) -> String {
        self.inner.username()
    }

    #[getter]
    pub fn email(&self) -> Option<String> {
        self.inner.email()
    }

    #[getter]
    pub fn id(&self) -> Option<String> {
        self.inner.id()
    }
}

#[cfg(feature = "python")]
#[pyclass(name = "IdpAuthHelper")]
pub struct PyIdpAuthHelper {
    inner: AuthHelper,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyIdpAuthHelper {
    #[new]
    fn new(certificate_pem: String) -> PyResult<Self> {
        let inner = AuthHelper::new(&certificate_pem)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        Ok(PyIdpAuthHelper { inner })
    }

    fn is_valid(&self, jwt: String) -> bool {
        self.inner.is_valid(&jwt)
    }

    /// Validates JWT and returns a CasdoorUser context object.
    /// This is the primary entry point.
    fn validate(&self, jwt: String) -> PyResult<PyCasdoorUser> {
        let user = self
            .inner
            .parse_user(&jwt)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        Ok(PyCasdoorUser { inner: user })
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn nf_ndc_connect_public(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIdpAuthHelper>()?;
    m.add_class::<PyCasdoorUser>()?;
    Ok(())
}

// =============================================================================
//  WASM / NPM BINDINGS
// =============================================================================

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = CasdoorUser)]
pub struct WasmCasdoorUser {
    inner: CasdoorUser,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_class = CasdoorUser)]
impl WasmCasdoorUser {
    #[wasm_bindgen(getter)]
    pub fn summaries(&self) -> Result<JsValue, JsError> {
        serde_wasm_bindgen::to_value(&self.inner.summaries).map_err(Into::into)
    }

    #[wasm_bindgen(getter)]
    pub fn claims(&self) -> Result<JsValue, JsError> {
        serde_wasm_bindgen::to_value(&self.inner.claims).map_err(Into::into)
    }

    #[wasm_bindgen(js_name = hasGroup)]
    pub fn has_group(&self, group_name: &str) -> bool {
        self.inner.has_group(group_name)
    }

    #[wasm_bindgen(js_name = hasRole)]
    pub fn has_role(&self, role_name: &str, group_name: Option<String>) -> Result<bool, JsError> {
        self.inner
            .has_role(role_name, group_name.as_deref())
            .map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = hasPermission)]
    pub fn has_permission(
        &self,
        perm_name: &str,
        group_name: Option<String>,
    ) -> Result<bool, JsError> {
        self.inner
            .has_permission(perm_name, group_name.as_deref())
            .map_err(|e| JsError::new(&e))
    }

    /// Check if user has ALL provided permissions (Exhaustive).
    /// JS should pass an array of strings: `["read", "write"]`
    #[wasm_bindgen(js_name = hasPermissions)]
    pub fn has_permissions(
        &self,
        perm_names: Vec<String>,
        group_name: Option<String>,
    ) -> Result<bool, JsError> {
        self.inner
            .has_permissions(&perm_names, group_name.as_deref())
            .map_err(|e| JsError::new(&e))
    }

    /// Check if user has ANY provided permissions (Iterative).
    /// JS should pass an array of strings: `["read", "write"]`
    #[wasm_bindgen(js_name = hasPermissionsAny)]
    pub fn has_permissions_any(
        &self,
        perm_names: Vec<String>,
        group_name: Option<String>,
    ) -> Result<bool, JsError> {
        self.inner
            .has_permissions_any(&perm_names, group_name.as_deref())
            .map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(getter = isAdmin)]
    pub fn is_admin(&self) -> bool {
        self.inner.is_admin()
    }

    #[wasm_bindgen(getter = isGlobalAdmin)]
    pub fn is_global_admin(&self) -> bool {
        self.inner.is_global_admin()
    }

    #[wasm_bindgen(js_name = getOrgCount)]
    pub fn get_org_count(&self) -> usize {
        self.inner.get_org_count()
    }

    #[wasm_bindgen(js_name = getFirstOrgShortCode)]
    pub fn get_first_org_short_code(&self) -> Option<String> {
        self.inner.get_first_org_short_code()
    }

    #[wasm_bindgen(getter = username)]
    pub fn username(&self) -> String {
        self.inner.username()
    }

    #[wasm_bindgen(getter = email)]
    pub fn email(&self) -> Option<String> {
        self.inner.email()
    }

    #[wasm_bindgen(getter = id)]
    pub fn id(&self) -> Option<String> {
        self.inner.id()
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = IdpAuthHelper)]
pub struct WasmIdpAuthHelper {
    inner: AuthHelper,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_class = IdpAuthHelper)]
impl WasmIdpAuthHelper {
    #[wasm_bindgen(constructor)]
    pub fn new(certificate_pem: &str) -> Result<WasmIdpAuthHelper, JsError> {
        let inner = AuthHelper::new(certificate_pem).map_err(|e| JsError::new(&e))?;
        Ok(WasmIdpAuthHelper { inner })
    }

    #[wasm_bindgen(js_name = isValid)]
    pub fn is_valid(&self, jwt: &str) -> bool {
        self.inner.is_valid(jwt)
    }

    /// Validates the JWT and returns a CasdoorUser object.
    #[wasm_bindgen(js_name = validate)]
    pub fn validate(&self, jwt: &str) -> Result<WasmCasdoorUser, JsError> {
        let user = self.inner.parse_user(jwt).map_err(|e| JsError::new(&e))?;
        Ok(WasmCasdoorUser { inner: user })
    }
}
