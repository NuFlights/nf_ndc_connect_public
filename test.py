import json

from nf_ndc_connect_public import IdpAuthHelper


def test_claims():
    # 1. Load the IDP Public Certificate (PEM format)
    with open("cert.pem", "r") as f:
        public_key = f.read()

    # 2. Load the Raw JWT string
    with open("sample-jwt.txt", "r") as f:
        raw_jwt = f.read().strip()

    print("🔐 Initializing Auth Helper with Public Key...")
    helper = IdpAuthHelper(public_key)
    print("✅ Auth Helper Ready")

    # 3. Validation Check
    is_valid = helper.is_valid(raw_jwt)
    print(f"   🔹 is_valid: {is_valid}")

    if not is_valid:
        print("❌ JWT is invalid. Stopping tests.")
        return

    # ... But to get data, we 'validate' to get the User Context Object
    print("🚀 Parsing User Context...")
    try:
        user = helper.validate(raw_jwt)
    except ValueError as e:
        print(f"❌ Validation failed: {e}")
        return

    # 4. List Groups (organizations)
    groups_str = user.get_auth_summary()
    summaries = json.loads(groups_str)

    print("\n📂 User Group Summaries:")
    for s in summaries:
        print(f"   🏢 org_short_code: {s['org_short_code']}")
        print(f"      🎭 Role: {s['role']}")
        for p in s["permissions"]:
            print(f"      🔑 Permission: {p}")

    # Use real values from the sample JWT
    test_group = "T-EK"
    test_role = "role_dhilipsiva_1"
    test_perm = "permission_dhilipsiva_1"

    # 5. Check role
    has_role = user.has_role(test_role, test_group)
    print(f"\n   🔹 has_role('{test_role}', '{test_group}'): {has_role}")

    # 6. Check single permission
    has_perm = user.has_permission(test_perm, test_group)
    print(f"   🔹 has_permission('{test_perm}', '{test_group}'): {has_perm}")

    # 7. Check MULTIPLE permissions (Exhaustive & Iterative)
    print("\n   🧪 Testing Multi-Permission Checks:")

    # 7a. has_permissions (ALL must exist)
    # T-EK has: permission_dhilipsiva_2, permission_dhilipsiva_1
    req_perms_all = ["permission_dhilipsiva_1", "permission_dhilipsiva_2"]
    has_all = user.has_permissions(req_perms_all, test_group)
    print(f"   🔹 has_permissions({req_perms_all}, '{test_group}'): {has_all}")

    # 7b. has_permissions_any (AT LEAST ONE must exist)
    req_perms_any = ["permission_dhilipsiva_1", "non_existent_perm_99"]
    has_any = user.has_permissions_any(req_perms_any, test_group)
    print(f"   🔹 has_permissions_any({req_perms_any}, '{test_group}'): {has_any}")

    # 8. Optional group — omit group_name (should error since user has 2 groups)
    print("\n   ⚙️  Testing optional group (no group_name passed):")
    try:
        result = user.has_permissions_any(["permission_dhilipsiva_1", "other"], None)
        print(f"   🔹 has_permissions_any([...]): {result}")
    except ValueError as e:
        print(f"   ⚠️  has_permissions_any([...]): ValueError — {e}")

    # 9. Admin checks
    print(f"\n   🔹 is_admin: {user.is_admin}")
    print(f"   🔹 is_global_admin: {user.is_global_admin}")
    print(f"   🔹 username: {user.username}")
    print(f"   🔹 email: {user.email}")
    print(f"   🔹 dj_id: {user.dj_id}")
    print(f"   🔹 org_short_codes: {user.org_short_codes}")


if __name__ == "__main__":
    test_claims()
