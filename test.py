import json
import nf_auth_helper

def test_claims():
    # 1. Load the IDP Public Certificate (PEM format)
    # Replace 'cert.pem' with your actual IDP public key file
    with open("cert.pem", "r") as f:
        public_key = f.read()

    # 2. Load the Raw JWT string
    with open("jwt.txt", "r") as f:
        raw_jwt = f.read().strip()

    print("🔐 Initializing Auth Helper with Public Key...")
    helper = nf_auth_helper.IdpAuthHelper(public_key)
    print("✅ Auth Helper Ready")

    # 3. Validation Check
    is_valid = helper.is_valid(raw_jwt)
    print(f"   🔹 is_valid: {is_valid}")

    if not is_valid:
        print("❌ JWT is invalid (expired, forged, or malformed). Stopping tests.")
        return

    # 4. Get Authorization Tree
    auth_tree_str = helper.get_org_authorisations(raw_jwt)
    auth_tree = json.loads(auth_tree_str)
    
    print("\n📂 Org Authorizations Tree:")
    for org in auth_tree:
        print(f"   🏢 Org: {org['org_name']} (ID: {org['org_id']}) - Default: {org['is_default']}")
        for role in org['roles']:
            print(f"      🎭 Role: {role['name']} - {role['description']}")
        for perm in org['permissions']:
            print(f"      🔑 Perm: {perm['name']}")

    # 5. Direct Role/Permission Checks (Implicit Validation)
    test_org = "dhilipsiva_dev/nf-apex" # Adjust to match your JSON data
    test_role = "nf-apex-adm"

    has_role = helper.has_role(raw_jwt, test_org, test_role)
    print(f"\n   🔹 has_role('{test_org}', '{test_role}'): {has_role}")

    # Negative Test
    has_perm = helper.has_permission(raw_jwt, test_org, "super_delete")
    print(f"   🔸 has_permission('{test_org}', 'super_delete'): {has_perm}")

if __name__ == "__main__":
    test_claims()
