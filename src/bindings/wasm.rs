use wasm_bindgen::prelude::*;

use crate::auth::AuthHelper;
use crate::structs::CasdoorUser;

#[wasm_bindgen(js_name = CasdoorUser)]
pub struct WasmCasdoorUser {
    inner: CasdoorUser,
}

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

    #[wasm_bindgen(js_name = getOrgCount)]
    pub fn get_org_count(&self) -> usize {
        self.inner.get_org_count()
    }

    #[wasm_bindgen(js_name = getFirstOrgShortCode)]
    pub fn get_first_org_short_code(&self) -> Option<String> {
        self.inner.get_first_org_short_code()
    }

    #[wasm_bindgen(js_name = getDefaultOrgShortCode)]
    pub fn get_default_org_short_code(&self) -> Option<String> {
        self.inner.get_default_org_short_code()
    }

    #[wasm_bindgen(getter = username)]
    pub fn username(&self) -> String {
        self.inner.username()
    }

    #[wasm_bindgen(getter = lastSigninTime)]
    pub fn last_signin_time(&self) -> Option<String> {
        self.inner.last_signin_time()
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

#[wasm_bindgen(js_name = IdpAuthHelper)]
pub struct WasmIdpAuthHelper {
    inner: AuthHelper,
}

#[wasm_bindgen(js_class = IdpAuthHelper)]
impl WasmIdpAuthHelper {
    #[wasm_bindgen(constructor)]
    pub fn new(certificate_pem: &str, group_prefix: String) -> Result<WasmIdpAuthHelper, JsError> {
        let inner = AuthHelper::new(certificate_pem, group_prefix).map_err(|e| JsError::new(&e))?;
        Ok(WasmIdpAuthHelper { inner })
    }

    #[wasm_bindgen(js_name = isValid)]
    pub fn is_valid(&self, jwt: &str) -> bool {
        self.inner.is_valid(jwt)
    }

    /// Validates the token and returns a CasdoorUser object.
    #[wasm_bindgen(js_name = validate)]
    pub fn validate(&self, jwt: &str) -> Result<WasmCasdoorUser, JsError> {
        let user = self.inner.parse_user(jwt).map_err(|e| JsError::new(&e))?;
        Ok(WasmCasdoorUser { inner: user })
    }
}
