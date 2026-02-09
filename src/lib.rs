use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
//  CASDOOR JWT STRUCTS (matched against real token payload)
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
    pub group: String,
    pub group_name: String,
    pub is_direct_member: bool,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
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

    pub fn validate(&self, jwt: &str) -> Result<CasdoorClaims, String> {
        decode::<CasdoorClaims>(jwt, &self.decoding_key, &self.validation)
            .map(|td| td.claims)
            .map_err(|e| format!("JWT Validation Failed: {}", e))
    }

    pub fn is_valid(&self, jwt: &str) -> bool {
        self.validate(jwt).is_ok()
    }

    // =========================================================================
    //  INTERNAL HELPERS
    // =========================================================================

    /// Fully qualify a group name: "my_group" → "owner/my_group".
    /// Already-qualified names ("owner/my_group") pass through unchanged.
    fn qualify_group(claims: &CasdoorClaims, group_name: &str) -> String {
        if group_name.contains('/') {
            group_name.to_string()
        } else {
            format!("{}/{}", claims.owner, group_name)
        }
    }

    /// Collect all unique fully-qualified group identifiers from:
    /// 1. Direct claims.groups
    /// 2. role.groups on each of the user's roles
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

    /// Resolve the target group when the caller didn't specify one.
    /// - 0 groups → error
    /// - 1 group  → use it as default
    /// - N groups → error (ambiguous)
    fn resolve_group(claims: &CasdoorClaims, group_name: Option<&str>) -> Result<String, String> {
        if let Some(name) = group_name {
            return Ok(Self::qualify_group(claims, name));
        }

        let groups = Self::collect_all_groups(claims);
        match groups.len() {
            0 => Err("No group specified and user belongs to no groups.".to_string()),
            1 => Ok(groups.into_iter().next().unwrap()),
            n => {
                let names: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
                Err(format!(
                    "No group specified and user belongs to {} groups: [{}]. Explicit group required.",
                    n,
                    names.join(", ")
                ))
            }
        }
    }

    /// Get roles scoped to a specific fully-qualified group.
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

    /// Check if a role ref ("owner/role_name") from a permission is among the
    /// user's roles that are scoped to the target group.
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

    // =========================================================================
    //  1. LIST GROUPS
    // =========================================================================

    pub fn list_groups(&self, jwt: &str) -> Result<Vec<GroupAuthSummary>, String> {
        let claims = self.validate(jwt)?;

        let user_roles = claims.roles.as_deref().unwrap_or(&[]);
        let user_perms = claims.permissions.as_deref().unwrap_or(&[]);
        let direct_groups = claims.groups.as_deref().unwrap_or(&[]);
        let all_groups = Self::collect_all_groups(&claims);

        let mut summaries = Vec::new();
        for group_fq in &all_groups {
            let group_name = group_fq
                .split_once('/')
                .map(|(_, n)| n.to_string())
                .unwrap_or_else(|| group_fq.clone());

            let is_direct = direct_groups.contains(group_fq);

            let role_names: Vec<String> = Self::roles_for_group(user_roles, group_fq)
                .iter()
                .map(|r| r.name.clone())
                .collect();

            let perm_names: Vec<String> = user_perms
                .iter()
                .filter(|p| {
                    p.is_enabled
                        && p.roles.as_ref().is_some_and(|perm_roles| {
                            perm_roles.iter().any(|role_ref| {
                                Self::user_has_role_ref_for_group(user_roles, role_ref, group_fq)
                            })
                        })
                })
                .map(|p| p.name.clone())
                .collect();

            summaries.push(GroupAuthSummary {
                group: group_fq.clone(),
                group_name,
                is_direct_member: is_direct,
                roles: role_names,
                permissions: perm_names,
            });
        }

        Ok(summaries)
    }

    // =========================================================================
    //  2. HAS GROUP
    // =========================================================================

    /// Check if user belongs to a group (direct or via role).
    /// `group_name`: short ("my_group") or qualified ("owner/my_group").
    /// Not optional here — this is the "check" method, not "act within" method.
    pub fn has_group(&self, jwt: &str, group_name: &str) -> Result<bool, String> {
        let claims = self.validate(jwt)?;
        let group_fq = Self::qualify_group(&claims, group_name);
        let all_groups = Self::collect_all_groups(&claims);
        Ok(all_groups.iter().any(|g| g == &group_fq))
    }

    // =========================================================================
    //  3. HAS ROLE FOR GROUP
    // =========================================================================

    /// Check if user has `role_name` scoped to a group.
    /// If `group_name` is None:
    ///   - 1 group  → uses it as default
    ///   - 0 or >1  → returns error
    pub fn has_role_for_group(
        &self,
        jwt: &str,
        role_name: &str,
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let claims = self.validate(jwt)?;
        let group_fq = Self::resolve_group(&claims, group_name)?;
        let user_roles = claims.roles.as_deref().unwrap_or(&[]);

        Ok(user_roles.iter().any(|r| {
            r.name == role_name
                && r.is_enabled
                && r.groups
                    .as_ref()
                    .is_some_and(|gs| gs.iter().any(|g| g == &group_fq))
        }))
    }

    // =========================================================================
    //  4. HAS PERMISSION FOR GROUP
    // =========================================================================

    /// Check if user has `perm_name` that traces to a group through the role chain.
    /// If `group_name` is None:
    ///   - 1 group  → uses it as default
    ///   - 0 or >1  → returns error
    pub fn has_permission_for_group(
        &self,
        jwt: &str,
        perm_name: &str,
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let claims = self.validate(jwt)?;
        let group_fq = Self::resolve_group(&claims, group_name)?;
        let user_roles = claims.roles.as_deref().unwrap_or(&[]);
        let user_perms = claims.permissions.as_deref().unwrap_or(&[]);

        Ok(user_perms.iter().any(|p| {
            p.name == perm_name
                && p.is_enabled
                && p.roles.as_ref().is_some_and(|perm_roles| {
                    perm_roles.iter().any(|role_ref| {
                        Self::user_has_role_ref_for_group(user_roles, role_ref, &group_fq)
                    })
                })
        }))
    }

    // =========================================================================
    //  ADMIN CHECKS
    // =========================================================================

    pub fn is_admin(&self, jwt: &str) -> Result<bool, String> {
        Ok(self.validate(jwt)?.is_admin)
    }

    pub fn is_global_admin(&self, jwt: &str) -> Result<bool, String> {
        Ok(self.validate(jwt)?.is_global_admin)
    }
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
    fn new(certificate_pem: String) -> PyResult<Self> {
        let inner = AuthHelper::new(&certificate_pem)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        Ok(PyIdpAuthHelper { inner })
    }

    fn is_valid(&self, jwt: String) -> bool {
        self.inner.is_valid(&jwt)
    }

    fn validate(&self, jwt: String) -> PyResult<String> {
        let claims = self
            .inner
            .validate(&jwt)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        serde_json::to_string(&claims)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn list_groups(&self, jwt: String) -> PyResult<String> {
        let groups = self
            .inner
            .list_groups(&jwt)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        serde_json::to_string(&groups)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn has_group(&self, jwt: String, group_name: String) -> PyResult<bool> {
        self.inner
            .has_group(&jwt, &group_name)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    /// group_name: Optional[str] = None
    /// Raises ValueError if group_name is None and user has 0 or >1 groups.
    #[pyo3(signature = (jwt, role_name, group_name=None))]
    fn has_role_for_group(
        &self,
        jwt: String,
        role_name: String,
        group_name: Option<String>,
    ) -> PyResult<bool> {
        self.inner
            .has_role_for_group(&jwt, &role_name, group_name.as_deref())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    /// group_name: Optional[str] = None
    /// Raises ValueError if group_name is None and user has 0 or >1 groups.
    #[pyo3(signature = (jwt, perm_name, group_name=None))]
    fn has_permission_for_group(
        &self,
        jwt: String,
        perm_name: String,
        group_name: Option<String>,
    ) -> PyResult<bool> {
        self.inner
            .has_permission_for_group(&jwt, &perm_name, group_name.as_deref())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    fn is_admin(&self, jwt: String) -> PyResult<bool> {
        self.inner
            .is_admin(&jwt)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }

    fn is_global_admin(&self, jwt: String) -> PyResult<bool> {
        self.inner
            .is_global_admin(&jwt)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn nf_ndc_connect_public(m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    pub fn new(certificate_pem: &str) -> Result<WasmIdpAuthHelper, JsError> {
        let inner = AuthHelper::new(certificate_pem).map_err(|e| JsError::new(&e))?;
        Ok(WasmIdpAuthHelper { inner })
    }

    #[wasm_bindgen(js_name = isValid)]
    pub fn is_valid(&self, jwt: &str) -> bool {
        self.inner.is_valid(jwt)
    }

    #[wasm_bindgen(js_name = validate)]
    pub fn validate(&self, jwt: &str) -> Result<JsValue, JsError> {
        let claims = self.inner.validate(jwt).map_err(|e| JsError::new(&e))?;
        serde_wasm_bindgen::to_value(&claims).map_err(Into::into)
    }

    #[wasm_bindgen(js_name = listGroups)]
    pub fn list_groups(&self, jwt: &str) -> Result<JsValue, JsError> {
        let groups = self.inner.list_groups(jwt).map_err(|e| JsError::new(&e))?;
        serde_wasm_bindgen::to_value(&groups).map_err(Into::into)
    }

    #[wasm_bindgen(js_name = hasGroup)]
    pub fn has_group(&self, jwt: &str, group_name: &str) -> Result<bool, JsError> {
        self.inner
            .has_group(jwt, group_name)
            .map_err(|e| JsError::new(&e))
    }

    /// group_name is optional (pass null/undefined in JS).
    /// Throws Error if null and user has 0 or >1 groups.
    #[wasm_bindgen(js_name = hasRoleForGroup)]
    pub fn has_role_for_group(
        &self,
        jwt: &str,
        role_name: &str,
        group_name: Option<String>,
    ) -> Result<bool, JsError> {
        self.inner
            .has_role_for_group(jwt, role_name, group_name.as_deref())
            .map_err(|e| JsError::new(&e))
    }

    /// group_name is optional (pass null/undefined in JS).
    /// Throws Error if null and user has 0 or >1 groups.
    #[wasm_bindgen(js_name = hasPermissionForGroup)]
    pub fn has_permission_for_group(
        &self,
        jwt: &str,
        perm_name: &str,
        group_name: Option<String>,
    ) -> Result<bool, JsError> {
        self.inner
            .has_permission_for_group(jwt, perm_name, group_name.as_deref())
            .map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = isAdmin)]
    pub fn is_admin(&self, jwt: &str) -> Result<bool, JsError> {
        self.inner.is_admin(jwt).map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = isGlobalAdmin)]
    pub fn is_global_admin(&self, jwt: &str) -> Result<bool, JsError> {
        self.inner
            .is_global_admin(jwt)
            .map_err(|e| JsError::new(&e))
    }
}
