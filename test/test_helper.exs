Logger.configure(level: :warn)

ExUnit.start()

# Setting up the database with dummy user model
Mix.Task.run("ecto.drop", ~w(--quiet))
Mix.shell.cmd("rm priv/test/migrations/*_create_oauth_tables.exs")
case System.get_env("UUID") do
  nil -> Mix.Task.run("ex_oauth2_provider.install", ~w(--no-config))
  uuid -> Mix.Task.run("ex_oauth2_provider.install", ~w(--no-config --uuid #{uuid}))
end
Mix.Task.run("ecto.create", ~w(--quiet))
Mix.Task.run("ecto.migrate")


{:ok, _pid} = ExOauth2Provider.Test.Repo.start_link()
Ecto.Adapters.SQL.Sandbox.mode(ExOauth2Provider.Test.Repo, :manual)
