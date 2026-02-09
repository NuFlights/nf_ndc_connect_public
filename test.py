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
    # We can check validity quickly without parsing everything...
    is_valid = helper.is_valid(raw_jwt)
    print(f"   🔹 is_valid: {is_valid}")

    if not is_valid:
        print("❌ JWT is invalid. Stopping tests.")
        return

    # ... But to get data, we 'validate' to get the User Context Object
    print("🚀 Parsing User Context...")
    try:
        user = helper.validate(raw_jwt)
        print("USER: ", user)
    except ValueError as e:
        print(f"❌ Validation failed: {e}")
        return

    # 4. List Groups (organizations) the user belongs to
    # Note: method called on 'user', returns JSON string
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

    # 5. Check group membership
    test_group = "group_test_dhilipsiva1"  # Adjust to match your data

    # Method called on 'user', no jwt arg needed
    has_grp = user.has_group(test_group)
    print(f"\n   🔹 has_group('{test_group}'): {has_grp}")

    has_grp_no = user.has_group("nonexistent_group")
    print(f"   🔸 has_group('nonexistent_group'): {has_grp_no}")

    # 6. Check role for a specific group
    test_role = "role_dhilipsiva_1"  # Adjust to match your data

    # Renamed from has_role_for_group -> has_role
    has_role = user.has_role(test_role, test_group)
    print(f"\n   🔹 has_role('{test_role}', '{test_group}'): {has_role}")

    # Negative: role exists but on a different group
    has_role_wrong = user.has_role("role_dhilipsiva_2", test_group)
    print(f"   🔸 has_role('role_dhilipsiva_2', '{test_group}'): {has_role_wrong}")

    # 7. Check permission for a specific group
    test_perm = "permission_dhilipsiva_1"  # Adjust to match your data

    # Renamed from has_permission_for_group -> has_permission
    has_perm = user.has_permission(test_perm, test_group)
    print(f"\n   🔹 has_permission('{test_perm}', '{test_group}'): {has_perm}")

    # Negative: permission traces to a different group only
    has_perm_no = user.has_permission("permission_dhilipsiva_3", test_group)
    print(
        f"   🔸 has_permission('permission_dhilipsiva_3', '{test_group}'): {has_perm_no}"
    )

    # 8. Optional group — omit group_name (should error if user has >1 group)
    print("\n   ⚙️  Testing optional group (no group_name passed):")
    try:
        result = user.has_role(test_role)
        print(f"   🔹 has_role('{test_role}'): {result}")
    except ValueError as e:
        print(f"   ⚠️  has_role('{test_role}'): ValueError — {e}")

    try:
        result = user.has_permission(test_perm)
        print(f"   🔹 has_permission('{test_perm}'): {result}")
    except ValueError as e:
        print(f"   ⚠️  has_permission('{test_perm}'): ValueError — {e}")

    # 9. Admin checks (Properties, not methods)
    print(f"\n   🔹 is_admin: {user.is_admin}")
    print(f"   🔹 is_global_admin: {user.is_global_admin}")


if __name__ == "__main__":
    test_claims()
