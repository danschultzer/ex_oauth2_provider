alias ExOauth2Provider.Test.Repo

additional_opts = if System.get_env("UUID"), do: ["--uuid", System.get_env("UUID")], else: []
install_opts = Enum.concat(["--no-config"], additional_opts)

# Setting up the database with dummy user model
Mix.Task.run "ecto.drop", ~w(--quiet)
Mix.shell.cmd("rm priv/test/migrations/*_create_oauth_tables.exs")
Mix.Task.run "ex_oauth2_provider.install", install_opts
Mix.Task.run "ecto.create", ~w(--quiet)
Mix.Task.run "ecto.migrate"

# For tasks/generators testing
Mix.start()
Mix.shell(Mix.Shell.Process)
Logger.configure(level: :info)

ExUnit.start()

{:ok, _pid} = Repo.start_link

Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)
