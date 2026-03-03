mod structs;
mod auth;
mod bindings;

#[cfg(feature = "login")]
mod login;

// Re-export the public API
pub use structs::*;
pub use auth::*;

#[cfg(feature = "login")]
pub use login::*;

// =============================================================================
//  PYTHON MODULE REGISTRATION
// =============================================================================

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
fn nf_ndc_connect_public(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<bindings::python::PyIdpAuthHelper>()?;
    m.add_class::<bindings::python::PyCasdoorUser>()?;
    #[cfg(feature = "login")]
    m.add_function(pyo3::wrap_pyfunction!(bindings::python::py_login, m)?)?;
    Ok(())
}
