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
    helper = IdpAuthHelper(public_key, "connect-development")
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
        print(f"   org_short_code: {s['group']}")
        print(f"      Role: {s['role']}")
        for p in s["permissions"]:
            print(f"      Permission: {p}")

    # Use real values from the sample JWT
    # Single role: account.custom.KEixtFTW
    # Single group: connect-development/connect-development_T-2345
    # After stripping group_prefix "connect-development_", short code = "T-2345"
    test_group = "T-2345"
    test_role = "account.custom.KEixtFTW"
    test_perm_1 = "agencies.view"
    test_perm_2 = "travel.orders.create"
    test_perm_nonexistent = "nonexistent.permission"

    # 5. Check role
    has_role = user.has_role(test_role, test_group)
    print(f"\n   has_role('{test_role}', '{test_group}'): {has_role}")
    assert has_role, f"Expected {test_role} in {test_group}"

    # 6. Check single permission
    has_perm = user.has_permission(test_perm_1, test_group)
    print(f"   has_permission('{test_perm_1}', '{test_group}'): {has_perm}")
    assert has_perm, f"Expected {test_perm_1} in {test_group}"

    has_perm_2 = user.has_permission(test_perm_2, test_group)
    print(f"   has_permission('{test_perm_2}', '{test_group}'): {has_perm_2}")
    assert has_perm_2, f"Expected {test_perm_2} in {test_group}"

    # Non-existent permission should be false
    has_perm_none = user.has_permission(test_perm_nonexistent, test_group)
    print(
        f"   has_permission('{test_perm_nonexistent}', '{test_group}'): {has_perm_none}"
    )
    assert not has_perm_none, f"Expected {test_perm_nonexistent} NOT in {test_group}"

    # 7. Check MULTIPLE permissions (Exhaustive & Iterative)
    print("\n   Testing Multi-Permission Checks:")

    # 7a. has_permissions (ALL must exist)
    req_perms_all = ["agencies.view", "travel.orders.create"]
    has_all = user.has_permissions(req_perms_all, test_group)
    print(f"   has_permissions({req_perms_all}, '{test_group}'): {has_all}")
    assert has_all, "Expected all permissions in group"

    # 7b. has_permissions_any (AT LEAST ONE must exist)
    req_perms_any = ["agencies.view", "nonexistent.perm"]
    has_any = user.has_permissions_any(req_perms_any, test_group)
    print(f"   has_permissions_any({req_perms_any}, '{test_group}'): {has_any}")
    assert has_any, "Expected at least one permission match"

    # 8. Optional group -- omit group_name (should work since user has only 1 group)
    print("\n   Testing optional group (no group_name passed):")
    result = user.has_permission("agencies.view", None)
    print(f"   has_permission('agencies.view', None): {result}")
    assert result, "Expected permission found when group is inferred (single group)"

    # 9. has_group check
    assert user.has_group(test_group), f"Expected has_group for {test_group}"
    assert not user.has_group(
        "nonexistent_group"
    ), "Expected no match for nonexistent group"

    # 10. User property checks
    print(f"\n   is_admin: {user.is_admin}")
    print(f"   username: {user.username}")
    print(f"   email: {user.email}")
    print(f"   dj_id: {user.dj_id}")
    print(f"   org_short_codes: {user.org_short_codes}")
    print(f"   get_org_count: {user.get_org_count()}")
    print(f"   get_first_org_short_code: {user.get_first_org_short_code()}")

    assert user.username == "ishahid0086_ek_gmail_com"
    assert user.email == "ishahid0086+ek@gmail.com"
    assert user.is_admin is True
    assert user.dj_id == "eabeab05-146e-4552-8cc5-3a992be15ea5"
    assert user.get_org_count() == 1
    assert user.get_first_org_short_code() == "T-2345"
    assert user.org_short_codes == ["T-2345"]

    print("\nAll assertions passed!")


def test_login():
    if not HAS_LOGIN:
        print(
            "\nLogin feature not available (built without 'login' feature). Skipping."
        )
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
