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
        print("❌ JWT is invalid (expired, forged, or malformed). Stopping tests.")
        return

    # 4. List Groups (organizations) the user belongs to
    groups_str = helper.list_groups(raw_jwt)
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
    has_grp = helper.has_group(raw_jwt, test_group)
    print(f"\n   🔹 has_group('{test_group}'): {has_grp}")

    has_grp_no = helper.has_group(raw_jwt, "nonexistent_group")
    print(f"   🔸 has_group('nonexistent_group'): {has_grp_no}")

    # 6. Check role for a specific group
    test_role = "role_dhilipsiva_1"  # Adjust to match your data

    has_role = helper.has_role_for_group(raw_jwt, test_role, test_group)
    print(f"\n   🔹 has_role_for_group('{test_role}', '{test_group}'): {has_role}")

    # Negative: role exists but on a different group
    has_role_wrong = helper.has_role_for_group(raw_jwt, "role_dhilipsiva_2", test_group)
    print(
        f"   🔸 has_role_for_group('role_dhilipsiva_2', '{test_group}'): {has_role_wrong}"
    )

    # 7. Check permission for a specific group
    test_perm = "permission_dhilipsiva_1"  # Adjust to match your data

    has_perm = helper.has_permission_for_group(raw_jwt, test_perm, test_group)
    print(
        f"\n   🔹 has_permission_for_group('{test_perm}', '{test_group}'): {has_perm}"
    )

    # Negative: permission traces to a different group only
    has_perm_no = helper.has_permission_for_group(
        raw_jwt, "permission_dhilipsiva_3", test_group
    )
    print(
        f"   🔸 has_permission_for_group('permission_dhilipsiva_3', '{test_group}'): {has_perm_no}"
    )

    # 8. Optional group — omit group_name (should error if user has >1 group)
    print("\n   ⚙️  Testing optional group (no group_name passed):")
    try:
        result = helper.has_role_for_group(raw_jwt, test_role)
        print(f"   🔹 has_role_for_group('{test_role}'): {result}")
    except ValueError as e:
        print(f"   ⚠️  has_role_for_group('{test_role}'): ValueError — {e}")

    try:
        result = helper.has_permission_for_group(raw_jwt, test_perm)
        print(f"   🔹 has_permission_for_group('{test_perm}'): {result}")
    except ValueError as e:
        print(f"   ⚠️  has_permission_for_group('{test_perm}'): ValueError — {e}")

    # 9. Admin checks
    print(f"\n   🔹 is_admin: {helper.is_admin(raw_jwt)}")
    print(f"   🔹 is_global_admin: {helper.is_global_admin(raw_jwt)}")


if __name__ == "__main__":
    test_claims()
