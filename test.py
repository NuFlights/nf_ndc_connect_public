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
    groups = json.loads(groups_str)

    print("\n📂 User Groups:")
    for g in groups:
        direct = " (direct)" if g["is_direct_member"] else " (via role)"
        print(f"   🏢 {g['group_name']} [{g['group']}]{direct}")
        for r in g["roles"]:
            print(f"      🎭 Role: {r}")
        for p in g["permissions"]:
            print(f"      🔑 Permission: {p}")

    test_group = "group_test_dhilipsiva1"  # Adjust to match your data
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
    req_perms_all = [test_perm, "permission_dhilipsiva_2"] # Assuming 2 exists, otherwise false
    has_all = user.has_permissions(req_perms_all, test_group)
    print(f"   🔹 has_permissions({req_perms_all}, '{test_group}'): {has_all}")

    # 7b. has_permissions_any (AT LEAST ONE must exist)
    req_perms_any = [test_perm, "non_existent_perm_99"] 
    has_any = user.has_permissions_any(req_perms_any, test_group)
    print(f"   🔹 has_permissions_any({req_perms_any}, '{test_group}'): {has_any}")

    # 8. Optional group — omit group_name
    print("\n   ⚙️  Testing optional group (no group_name passed):")
    try:
        result = user.has_permissions_any([test_perm, "other"], None)
        print(f"   🔹 has_permissions_any([...]): {result}")
    except ValueError as e:
        print(f"   ⚠️  has_permissions_any([...]): ValueError — {e}")

    # 9. Admin checks
    print(f"\n   🔹 is_admin: {user.is_admin}")
    print(f"   🔹 is_global_admin: {user.is_global_admin}")


if __name__ == "__main__":
    test_claims()
