use Mix.Config

config :ex_oauth2_provider, namespace: Dummy

config :ex_oauth2_provider, ExOauth2Provider,
  repo: Dummy.Repo,
  resource_owner: Dummy.Users.User,
  default_scopes: ~w(public),
  optional_scopes: ~w(read write),
  password_auth: {Dummy.Auth, :auth},
  use_refresh_token: true,
  revoke_refresh_token_on_use: true,
  grant_flows: ~w(authorization_code client_credentials)

config :ex_oauth2_provider, Dummy.Repo,
  database: "ex_oauth2_provider_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  priv: "test/support/priv"
