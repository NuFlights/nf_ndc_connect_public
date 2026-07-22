use pyo3::prelude::*;

use crate::auth::AuthHelper;
use crate::structs::CasdoorUser;

#[pyclass(name = "CasdoorUser")]
pub struct PyCasdoorUser {
    inner: CasdoorUser,
}

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

    pub fn get_org_count(&self) -> usize {
        self.inner.get_org_count()
    }

    pub fn get_first_org_short_code(&self) -> Option<String> {
        self.inner.get_first_org_short_code()
    }

    pub fn get_default_org_short_code(&self) -> Option<String> {
        self.inner.get_default_org_short_code()
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
    pub fn last_signin_time(&self) -> Option<String> {
        self.inner.last_signin_time()
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

#[pyclass(name = "IdpAuthHelper")]
pub struct PyIdpAuthHelper {
    inner: AuthHelper,
}

#[pymethods]
impl PyIdpAuthHelper {
    #[new]
    fn new(certificate_pem: String, group_prefix: String) -> PyResult<Self> {
        let inner = AuthHelper::new(&certificate_pem, group_prefix)
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

#[cfg(feature = "login")]
#[pyfunction]
#[pyo3(name = "login")]
pub fn py_login(
    idp_base_url: String,
    client_id: String,
    client_secret: String,
    username: String,
    password: String,
) -> PyResult<String> {
    let response = crate::login::login(
        &idp_base_url,
        &client_id,
        &client_secret,
        &username,
        &password,
    )
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;

    serde_json::to_string(&response)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
