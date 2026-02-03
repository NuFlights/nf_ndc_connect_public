# nf_ndc_connect_public

**One Logic, Three Platforms.**
This library provides a unified, secure, and high-performance Identity Provider (IDP) Claims & Authorization helper. It is written in **Rust** and compiled for:

* **Rust** (Native Crate)
* **Python** (via PyO3)
* **Node.js / Web** (via Wasm-Pack)

It handles JWT validation, Role-Based Access Control (RBAC) checks, and parsing of complex IDP organization trees.

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

## 🚀 Usage

### 🐍 Python Example

```python
import nf_ndc_connect_public
import json

# 1. Initialize with your Public Key (PEM format)
with open("cert.pem", "r") as f:
    public_key = f.read()

helper = nf_ndc_connect_public.IdpAuthHelper(public_key)

# 2. Validate a JWT
raw_jwt = "eyJhbGciOiJ..."
if helper.is_valid(raw_jwt):
    print("✅ JWT is valid!")

    # 3. Check specific Roles or Permissions
    org_id = "dhilipsiva_dev/nf-apex"
    if helper.has_role(raw_jwt, org_id, "nf-apex-adm"):
        print("User is an Admin!")

    # 4. Get full authorization tree (returns JSON string)
    tree_json = helper.get_org_authorisations(raw_jwt)
    print(json.loads(tree_json))
else:
    print("❌ Invalid or Expired Token")

```

### 📦 Node.js Example

```javascript
const { IdpAuthHelper } = require("@dhilipsiva/nf_ndc_connect_public");
const fs = require("fs");

// 1. Initialize
const publicKey = fs.readFileSync("./cert.pem", "utf8");
const helper = new IdpAuthHelper(publicKey);

const rawJwt = "eyJhbGciOiJ...";

// 2. Validate
const isValid = helper.isValid(rawJwt);
console.log(`Is Valid? ${isValid}`);

if (isValid) {
    // 3. Check Role
    const hasRole = helper.hasRole(rawJwt, "dhilipsiva_dev/nf-apex", "nf-apex-adm");
    console.log(`Has Admin Role? ${hasRole}`);

    // 4. Get Auth Tree
    // Returns a native JS object (not a string) in Node
    const tree = helper.getOrgAuthorisations(rawJwt);
    console.log(tree);
}

```

### 🦀 Rust Example

```rust
use nf_ndc_connect_public::AuthHelper;

fn main() {
    let public_key = include_str!("../cert.pem");
    let helper = AuthHelper::new(public_key).expect("Invalid Key");
    
    let jwt = "eyJhbGciOiJ...";

    match helper.is_valid(jwt) {
        Ok(claims) => {
            println!("✅ Valid Token for subject: {}", claims.sub);
            
            if helper.has_role(jwt, "dhilipsiva_dev/nf-apex", "nf-apex-adm") {
                println!("User is Admin");
            }
        },
        Err(e) => println!("❌ Error: {}", e),
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
| `just wasm` | Build the Wasm package for Node.js |
| `just test` | Run standard Cargo tests |
| `just clean` | Remove all build artifacts (`target/`, `pkg/`, `.venv/`) |

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
