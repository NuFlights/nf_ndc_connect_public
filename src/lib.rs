use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

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
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub is_enabled: bool,
}

impl CasdoorRole {
    /// Returns the fully-qualified role reference: `{owner}/{name}`
    #[inline]
    pub fn qualified_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorPermission {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub actions: Option<Vec<String>>,
    #[serde(default)]
    pub is_enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorClaims {
    // --- User identity ---
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub id_card: String,
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
    pub roles: Vec<CasdoorRole>,
    #[serde(default)]
    pub permissions: Vec<CasdoorPermission>,
}

// =============================================================================
//  OUTPUT STRUCTURES
// =============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupAuthSummary {
    pub org_short_code: String,
    pub role: String,
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
    pub fn new(claims: CasdoorClaims) -> Result<Self, String> {
        let summaries = Self::compute_summaries(&claims)?;
        Ok(Self { claims, summaries })
    }

    /// Internal logic to pre-calculate the authentication summaries.
    fn compute_summaries(claims: &CasdoorClaims) -> Result<Vec<GroupAuthSummary>, String> {
        let mut summaries = Vec::with_capacity(claims.roles.len());

        for role in &claims.roles {
            let group = role.groups.first().ok_or_else(|| {
                format!(
                    "Role '{}' has no group association; exactly 1 is required",
                    role.name
                )
            })?;

            let org_short_code = group
                .split_once('/')
                .map(|(_, name)| name.to_string())
                .ok_or_else(|| {
                    format!(
                        "Group '{}' is not fully qualified (expected '{{owner}}/{{name}}')",
                        group
                    )
                })?;

            let qualified_role = role.qualified_name();

            let perm_names: Vec<String> = claims
                .permissions
                .iter()
                .filter(|p| {
                    p.is_enabled
                        && p.roles.as_ref().is_some_and(|perm_roles| {
                            perm_roles
                                .iter()
                                .any(|role_ref| role_ref == &qualified_role)
                        })
                })
                .map(|p| p.name.clone())
                .collect();

            summaries.push(GroupAuthSummary {
                org_short_code,
                role: role.name.clone(),
                permissions: perm_names,
            });
        }
        Ok(summaries)
    }

    // -------------------------------------------------------------------------
    //  Group resolution helper (DRY)
    // -------------------------------------------------------------------------

    /// Resolves the target summary/summaries based on optional group_name.
    /// - If `group_name` is provided, returns the matching summary (or error).
    /// - If `None` and exactly 1 org exists, returns that summary.
    /// - Otherwise, errors with an ambiguity message.
    fn resolve_group(&self, group_name: Option<&str>) -> Result<&GroupAuthSummary, String> {
        match group_name {
            Some(g) => self
                .summaries
                .iter()
                .find(|s| s.org_short_code == g)
                .ok_or_else(|| format!("No summary found for group '{}'", g)),
            None if self.summaries.len() == 1 => self
                .summaries
                .first()
                .ok_or_else(|| "No group summaries available".into()),
            None => Err(format!(
                "Ambiguous: user belongs to {} groups; specify group_name explicitly",
                self.summaries.len()
            )),
        }
    }

    // -------------------------------------------------------------------------
    //  Query methods
    // -------------------------------------------------------------------------

    /// Check if user belongs to a group.
    pub fn has_group(&self, group_name: &str) -> bool {
        self.summaries
            .iter()
            .any(|s| s.org_short_code == group_name)
    }

    /// Check if user has a role. If `group_name` is `None`, infer the default
    /// group (only when exactly 1 exists).
    pub fn has_role(&self, role_name: &str, group_name: Option<&str>) -> Result<bool, String> {
        self.resolve_group(group_name)
            .map(|summary| summary.role == role_name)
    }

    /// Check if user has a single permission.
    pub fn has_permission(
        &self,
        perm_name: &str,
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        self.resolve_group(group_name)
            .map(|summary| summary.permissions.iter().any(|p| p == perm_name))
    }

    /// Check if user has ALL provided permissions (exhaustive).
    pub fn has_permissions(
        &self,
        perm_names: &[String],
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let summary = self.resolve_group(group_name)?;
        Ok(perm_names
            .iter()
            .all(|name| summary.permissions.iter().any(|p| p == name)))
    }

    /// Check if user has ANY of the provided permissions (existential).
    pub fn has_permissions_any(
        &self,
        perm_names: &[String],
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let summary = self.resolve_group(group_name)?;
        Ok(perm_names
            .iter()
            .any(|name| summary.permissions.iter().any(|p| p == name)))
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

    pub fn dj_id(&self) -> String {
        self.claims.id_card.clone()
    }

    pub fn get_org_short_codes(&self) -> Vec<String> {
        self.summaries
            .iter()
            .map(|s| s.org_short_code.clone())
            .collect()
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
            .map_err(|e| format!("Invalid RSA public key: {}", e))?;

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
            .map_err(|e| format!("JWT validation failed: {}", e))?;

        CasdoorUser::new(claims)
    }

    pub fn is_valid(&self, jwt: &str) -> bool {
        self.parse_user(jwt).is_ok()
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
    pub fn dj_id(&self) -> String {
        self.inner.dj_id()
    }

    #[getter]
    pub fn org_short_codes(&self) -> Vec<String> {
        self.inner.get_org_short_codes()
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

    #[wasm_bindgen(getter = dj_id)]
    pub fn dj_id(&self) -> String {
        self.inner.dj_id()
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
