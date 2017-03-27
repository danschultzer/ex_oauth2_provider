use Mix.Config

config :ex_oauth2_provider, ExOauth2Provider,
  repo: ExOauth2Provider.Test.Repo,
  resource_owner_model: Dummy.User,
  default_scopes: ~w(public),
  optional_scopes: ~w(read update)

config :ex_oauth2_provider, ecto_repos: [ExOauth2Provider.Test.Repo]

config :ex_oauth2_provider, ExOauth2Provider.Test.Repo,
  adapter: Ecto.Adapters.Postgres,
  database: "ex_oauth2_provider_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  priv: "priv/test"
