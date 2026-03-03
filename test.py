import json

from nf_ndc_connect_public import IdpAuthHelper

# Also test the login function import (feature-gated)
try:
    from nf_ndc_connect_public import login
    HAS_LOGIN = True
except ImportError:
    HAS_LOGIN = False


def test_claims():
    # 1. Load the IDP Public Certificate (PEM format)
    with open("cert.pem", "r") as f:
        public_key = f.read()

    # 2. Load the Raw JWT string
    with open("sample-jwt.txt", "r") as f:
        raw_jwt = f.read().strip()

    print("Initializing Auth Helper with Public Key...")
    helper = IdpAuthHelper(public_key)
    print("Auth Helper Ready")

    # 3. Validation Check
    is_valid = helper.is_valid(raw_jwt)
    print(f"   is_valid: {is_valid}")

    if not is_valid:
        print("JWT is invalid (likely expired). Stopping tests.")
        return

    # ... But to get data, we 'validate' to get the User Context Object
    print("Parsing User Context...")
    try:
        user = helper.validate(raw_jwt)
    except ValueError as e:
        print(f"Validation failed: {e}")
        return

    # 4. List Groups (organizations)
    groups_str = user.get_auth_summary()
    summaries = json.loads(groups_str)

    print("\nUser Group Summaries:")
    for s in summaries:
        print(f"   org_short_code: {s['org_short_code']}")
        print(f"      Role: {s['role']}")
        for p in s["permissions"]:
            print(f"      Permission: {p}")

    # Use real values from the sample JWT
    # role_dhilipsiva_1 belongs to group "vinod_test_dev/group_test_dhilipsiva1"
    # role_dhilipsiva_2 belongs to group "vinod_test_dev/group_test_dhilipsiva2"
    test_group_1 = "group_test_dhilipsiva1"
    test_group_2 = "group_test_dhilipsiva2"
    test_role_1 = "role_dhilipsiva_1"
    test_role_2 = "role_dhilipsiva_2"
    test_perm_1 = "permission_dhilipsiva_1"  # role_1 only
    test_perm_2 = "permission_dhilipsiva_2"  # both roles
    test_perm_3 = "permission_dhilipsiva_3"  # role_2 only

    # 5. Check role
    has_role = user.has_role(test_role_1, test_group_1)
    print(f"\n   has_role('{test_role_1}', '{test_group_1}'): {has_role}")
    assert has_role, "Expected role_dhilipsiva_1 in group_test_dhilipsiva1"

    has_role_2 = user.has_role(test_role_2, test_group_2)
    print(f"   has_role('{test_role_2}', '{test_group_2}'): {has_role_2}")
    assert has_role_2, "Expected role_dhilipsiva_2 in group_test_dhilipsiva2"

    # 6. Check single permission
    has_perm = user.has_permission(test_perm_1, test_group_1)
    print(f"   has_permission('{test_perm_1}', '{test_group_1}'): {has_perm}")
    assert has_perm, "Expected permission_dhilipsiva_1 in group_test_dhilipsiva1"

    # permission_dhilipsiva_2 references both roles, so available in both groups
    has_perm_shared = user.has_permission(test_perm_2, test_group_1)
    print(f"   has_permission('{test_perm_2}', '{test_group_1}'): {has_perm_shared}")
    assert has_perm_shared, "Expected permission_dhilipsiva_2 in group_test_dhilipsiva1"

    has_perm_shared_2 = user.has_permission(test_perm_2, test_group_2)
    print(f"   has_permission('{test_perm_2}', '{test_group_2}'): {has_perm_shared_2}")
    assert has_perm_shared_2, "Expected permission_dhilipsiva_2 in group_test_dhilipsiva2"

    # permission_dhilipsiva_3 is only in role_2 (group_test_dhilipsiva2)
    has_perm_3_in_g2 = user.has_permission(test_perm_3, test_group_2)
    print(f"   has_permission('{test_perm_3}', '{test_group_2}'): {has_perm_3_in_g2}")
    assert has_perm_3_in_g2, "Expected permission_dhilipsiva_3 in group_test_dhilipsiva2"

    has_perm_3_in_g1 = user.has_permission(test_perm_3, test_group_1)
    print(f"   has_permission('{test_perm_3}', '{test_group_1}'): {has_perm_3_in_g1}")
    assert not has_perm_3_in_g1, "Expected permission_dhilipsiva_3 NOT in group_test_dhilipsiva1"

    # 7. Check MULTIPLE permissions (Exhaustive & Iterative)
    print("\n   Testing Multi-Permission Checks:")

    # 7a. has_permissions (ALL must exist) - in group_test_dhilipsiva1
    # group_test_dhilipsiva1 has: permission_dhilipsiva_2, permission_dhilipsiva_1
    req_perms_all = ["permission_dhilipsiva_1", "permission_dhilipsiva_2"]
    has_all = user.has_permissions(req_perms_all, test_group_1)
    print(f"   has_permissions({req_perms_all}, '{test_group_1}'): {has_all}")
    assert has_all, "Expected all permissions in group_test_dhilipsiva1"

    # 7b. has_permissions_any (AT LEAST ONE must exist)
    req_perms_any = ["permission_dhilipsiva_1", "non_existent_perm_99"]
    has_any = user.has_permissions_any(req_perms_any, test_group_1)
    print(f"   has_permissions_any({req_perms_any}, '{test_group_1}'): {has_any}")
    assert has_any, "Expected at least one permission match"

    # 8. Optional group -- omit group_name (should error since user has 2 groups)
    print("\n   Testing optional group (no group_name passed):")
    try:
        result = user.has_permissions_any(["permission_dhilipsiva_1", "other"], None)
        print(f"   has_permissions_any([...]): {result}")
        assert False, "Expected ValueError for ambiguous group"
    except ValueError as e:
        print(f"   has_permissions_any([...]): ValueError -- {e}")

    # 9. has_group check
    assert user.has_group(test_group_1), "Expected has_group for group_test_dhilipsiva1"
    assert user.has_group(test_group_2), "Expected has_group for group_test_dhilipsiva2"
    assert not user.has_group("nonexistent_group"), "Expected no match for nonexistent group"

    # 10. Admin checks
    print(f"\n   is_admin: {user.is_admin}")
    print(f"   is_global_admin: {user.is_global_admin}")
    print(f"   username: {user.username}")
    print(f"   email: {user.email}")
    print(f"   dj_id: {user.dj_id}")
    print(f"   org_short_codes: {user.org_short_codes}")
    print(f"   get_org_count: {user.get_org_count()}")
    print(f"   get_first_org_short_code: {user.get_first_org_short_code()}")

    assert user.username == "test_user_dhilipsiva"
    assert user.email == "test_user_dhilipsiva@example.com"
    assert user.is_admin is False
    assert user.is_global_admin is False
    assert user.get_org_count() == 2
    assert set(user.org_short_codes) == {"group_test_dhilipsiva1", "group_test_dhilipsiva2"}

    print("\nAll assertions passed!")


def test_login():
    if not HAS_LOGIN:
        print("\nLogin feature not available (built without 'login' feature). Skipping.")
        return

    print("\nLogin function is available.")
    # NOTE: Actual login test requires a running IDP instance.
    # Uncomment below to test against a live IDP:
    #
    # result_json = login(
    #     "https://idp.nuflights.com",
    #     "your_client_id",
    #     "your_client_secret",
    #     "your_username",
    #     "your_password",
    # )
    # result = json.loads(result_json)
    # print(f"   access_token: {result['access_token'][:20]}...")
    # print(f"   token_type: {result.get('token_type')}")
    # print(f"   expires_in: {result.get('expires_in')}")


if __name__ == "__main__":
    test_claims()
    test_login()
