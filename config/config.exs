use Mix.Config

config :ex_oauth2_provider, ExOauth2Provider, repo: %{}

if Mix.env == :test do
  import_config "test.exs"
end
