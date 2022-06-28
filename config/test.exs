use Mix.Config

config :ex_oauth2_provider, namespace: Dummy

config :ex_oauth2_provider, ExOauth2Provider,
  default_scopes: ~w(public),
  device_flow_verification_uri: "https://test.site.net/device",
  grant_flows: ~w(
    authorization_code
    client_credentials
    device_code
  ),
  optional_scopes: ~w(read write),
  password_auth: {Dummy.Auth, :auth},
  repo: Dummy.Repo,
  resource_owner: Dummy.Users.User,
  revoke_refresh_token_on_use: true,
  use_refresh_token: true

config :ex_oauth2_provider, Dummy.Repo,
  database: "ex_oauth2_provider_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  priv: "test/support/priv",
  username: "postgres",
  password: "postgres"
