alias ExOauth2Provider.Test.Repo
# For repo handling
{:ok, _} = Application.ensure_all_started(:ex_machina)

# Setting up the database with dummy user model
Mix.Task.run "ex_oauth2_provider.install"
Mix.Task.run "ecto.create", ~w(--quiet)
Mix.Task.run "ecto.migrate"

# For tasks/generators testing
Mix.start()
Mix.shell(Mix.Shell.Process)
Logger.configure(level: :info)

ExUnit.start()

{:ok, _pid} = Repo.start_link

Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)
