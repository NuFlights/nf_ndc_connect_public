curl -X POST https://idp.nuflights.com/api/login/oauth/access_token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "client_id": "be9c1e80b7a0839f2632",
    "client_secret": "925d38fd5627161dea743409ea39400cf9724b88",
    "username": "test_user_dhilipsiva",
    "password": "test1234"
  }'
