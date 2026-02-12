# nf_ndc_connect_public

**One Logic, Three Platforms.**
This library provides a unified, secure, and high-performance Identity Provider (IDP) Claims & Authorization helper. It is written in **Rust** and compiled for:

* **Rust** (Native Crate)
* **Python** (via PyO3)
* **Node.js / Web** (via Wasm-Pack)

It handles JWT validation, Role-Based Access Control (RBAC) checks, and parsing of complex IDP organization trees efficiently by parsing the token **once** into a context object.

---

## 📦 Installation

### 🦀 Rust

```bash
cargo add nf_ndc_connect_public

```

### 🐍 Python

```bash
pip install nf_ndc_connect_public

```

### 📦 Node.js (npm)

```bash
npm install @dhilipsiva/nf_ndc_connect_public

```

---

## 🔑 Organization Context & Auto-Resolution

**New in this version:** The library now uses a **Context Object Pattern**. You validate the JWT once to get a `User` object, which holds the parsed state.

When checking roles or permissions on this `User` object:

* **Explicit Context:** If you provide an `group_id` (Organization ID), checks are performed strictly against that organization.
* **Auto-Resolution:** If you omit `group_id` (pass `None` / `null`):
* If the user belongs to **exactly one** organization, that organization is used automatically.
* If the user belongs to **multiple** organizations (or zero), the function returns an **Error** (Ambiguous Context).



---

## 🚀 Usage

### 🐍 Python Example

In Python, `helper.validate(jwt)` returns a `CasdoorUser` object. All checks are performed on this object.

```python
from nf_ndc_connect_public import IdpAuthHelper
import json

# 1. Initialize
with open("cert.pem", "r") as f:
    public_key = f.read()

helper = IdpAuthHelper(public_key)
raw_jwt = "eyJhbGciOiJ..."

# 2. Parse User Context
try:
    user = helper.validate(raw_jwt)
except ValueError as e:
    print(f"❌ Validation failed: {e}")
    exit(1)

# 3. Check Single Role/Permission (Explicit Context)
group_id = "dhilipsiva_dev/nf-apex"
if user.has_role("nf-apex-adm", group_id):
    print("User is Admin!")

# 4. Check Multiple Permissions
# has_permissions = ALL must match (AND)
if user.has_permissions(["read", "write"], group_id):
    print("User has full R/W access")

# has_permissions_any = AT LEAST ONE must match (OR)
if user.has_permissions_any(["edit", "admin"], group_id):
    print("User has elevated privileges")

# 5. Get full authorization tree
print(json.loads(user.get_auth_summary()))

```

### 📦 Node.js / Web Example

In JavaScript/TypeScript, `helper.validate(jwt)` returns a `CasdoorUser` object.

```javascript
import { IdpAuthHelper } from "@dhilipsiva/nf_ndc_connect_public";

const helper = new IdpAuthHelper(publicKey);
const user = helper.validate(rawJwt);

const groupId = "dhilipsiva_dev/nf-apex";

// 1. Single Check
if (user.hasPermission("write", groupId)) {
    console.log("Can write!");
}

// 2. Multiple Permissions (Exhaustive - AND)
// Returns true only if user has BOTH "read" AND "write"
if (user.hasPermissions(["read", "write"], groupId)) {
    console.log("Full Access");
}

// 3. Multiple Permissions (Iterative - OR)
// Returns true if user has EITHER "edit" OR "delete"
if (user.hasPermissionsAny(["edit", "delete"], groupId)) {
    console.log("Can modify content");
}

// 4. Auto-Resolution (Pass null for group)
try {
    user.hasPermissionsAny(["read"], null);
} catch (e) {
    console.error("Ambiguous Context:", e.message);
}

```

### 🦀 Rust Example

In Rust, `helper.parse_user(jwt)` returns a `CasdoorUser` struct.

```rust
use nf_ndc_connect_public::AuthHelper;

fn main() {
    let helper = AuthHelper::new(public_key).unwrap();
    let user = helper.parse_user(jwt).unwrap();
    
    let group = Some("dhilipsiva_dev/nf-apex");

    // 1. Single Check
    if user.has_permission("read", group).unwrap() {
        println!("Can read");
    }

    // 2. Multiple Checks (Vec<String>)
    let required = vec!["read".to_string(), "write".to_string()];
    
    // Check ALL
    if user.has_permissions(&required, group).unwrap() {
        println!("Has all permissions");
    }

    // Check ANY
    if user.has_permissions_any(&required, group).unwrap() {
        println!("Has at least one permission");
    }
}

```

---

## 🛠️ Development

This project uses **Nix** for a reproducible environment and **Just** for command automation.

### Prerequisites

1. Install [Nix](https://nixos.org/download.html).
2. Enable flakes.

### Setup

```bash
nix develop

```

### Build Commands (via `just`)

| Command | Description |
| --- | --- |
| `just py-dev` | Build Python wheel in debug mode & install to venv |
| `just py-build` | Build Python wheel for release |
| `just wasm` | Build the Wasm package for Node.js/Web |
| `just test` | Run standard Cargo tests |
