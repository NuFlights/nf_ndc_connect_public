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

# 1. Initialize with your Public Key (PEM format)
with open("cert.pem", "r") as f:
    public_key = f.read()

helper = IdpAuthHelper(public_key)
raw_jwt = "eyJhbGciOiJ..."

# 2. Check Validity (Fast check, no parsing)
if not helper.is_valid(raw_jwt):
    print("❌ Invalid Token")
    exit(1)

# 3. Parse User Context (Validates & Parses once)
try:
    user = helper.validate(raw_jwt)
    print(f"✅ User parsed: {user.is_admin}")
except ValueError as e:
    print(f"❌ Validation failed: {e}")
    exit(1)

# 4. Check Roles (Auto-Resolution)
# If user is in exactly 1 Org, this works. If multiple, raises ValueError.
try:
    if user.has_role("nf-apex-adm"):
        print("User is an Admin (Default Org)!")
except ValueError as e:
    print(f"⚠️ Ambiguous Context: {e}")

# 5. Check Roles (Explicit Context)
group_id = "dhilipsiva_dev/nf-apex"
if user.has_role("nf-apex-adm", group_id):
    print(f"User is an Admin in {group_id}!")

# 6. Get full authorization tree (returns JSON string)
print(json.loads(user.get_auth_summary()))

```

### 📦 Node.js / Web Example

In JavaScript/TypeScript, `helper.validate(jwt)` returns a `CasdoorUser` object.

```javascript
import { IdpAuthHelper } from "@dhilipsiva/nf_ndc_connect_public";

// 1. Initialize
const publicKey = "..."; // Load your PEM
const helper = new IdpAuthHelper(publicKey);
const rawJwt = "eyJhbGciOiJ...";

// 2. Validate & Get Context
if (!helper.isValid(rawJwt)) {
    console.error("❌ Invalid Token");
    return;
}

const user = helper.validate(rawJwt);
console.log("✅ User Context Parsed");

try {
    // 3. Check Role (Auto-Resolution)
    // Pass only the role name to attempt automatic org detection
    const hasRoleDefault = user.hasRole("nf-apex-adm");
    console.log(`Has Admin Role (Default Org)? ${hasRoleDefault}`);
    
} catch (e) {
    console.error("⚠️ Ambiguous Context:", e.message);
}

// 4. Check Role (Explicit Context)
// Pass role name AND group ID
const hasRoleExplicit = user.hasRole("nf-apex-adm", "dhilipsiva_dev/nf-apex");
console.log(`Has Admin Role (Explicit)? ${hasRoleExplicit}`);

// 5. Admin Flags
console.log(`Is Global Admin? ${user.isGlobalAdmin}`);

// 6. Get Auth Tree (Property)
console.log(user.summaries);

```

### 🦀 Rust Example

In Rust, `helper.parse_user(jwt)` returns a `CasdoorUser` struct.

```rust
use nf_ndc_connect_public::AuthHelper;

fn main() {
    let public_key = include_str!("../cert.pem");
    let helper = AuthHelper::new(public_key).expect("Invalid Key");
    let jwt = "eyJhbGciOiJ...";

    // 1. Parse User
    match helper.parse_user(jwt) {
        Ok(user) => {
            println!("✅ Valid Token for subject: {}", user.claims.sub);
            
            // 2. Check Role (Explicit Context)
            match user.has_role("nf-apex-adm", Some("dhilipsiva_dev/nf-apex")) {
                Ok(true) => println!("User is Admin in specific Org"),
                _ => println!("User is NOT Admin or group not found"),
            }

            // 3. Check Role (Auto-Resolution)
            // Pass None to attempt automatic org detection
            match user.has_role("nf-apex-adm", None) {
                Ok(true) => println!("User is Admin (Default Org)"),
                Ok(false) => println!("User is NOT Admin"),
                Err(e) => println!("⚠️ Ambiguous Context: {}", e),
            }
        },
        Err(e) => println!("❌ Validation Error: {}", e),
    }
}

```

---

## 🛠️ Development

This project uses **Nix** for a reproducible environment and **Just** for command automation.

### Prerequisites

1. Install [Nix](https://nixos.org/download.html).
2. Enable flakes (standard in newer installers).

### Setup

Enter the development shell. This installs Rust, Python, Maturin, Node.js, and Wasm-Pack automatically.

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
| `just clean` | Remove all build artifacts |

### 🚢 Release Process

To publish a new version to PyPI, NPM, and Crates.io simultaneously:

1. **Ensure you are in the Nix shell** (`nix develop`).
2. **Run the release command:**

```bash
# Usage: just release <version>
just release 0.2.3

```

This will:

* Update `Cargo.toml` and `pyproject.toml`.
* Run checks.
* Commit the changes.
* Create a git tag `v0.2.3`.

3. **Push to trigger CI/CD:**

```bash
git push && git push --tags

```
