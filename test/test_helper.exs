alias ExOauth2Provider.Test.Repo
# For repo handling
{:ok, _} = Application.ensure_all_started(:ex_machina)

# Setting up the database with dummy user model
Path.relative_to(Mix.Ecto.migrations_path(Repo), Mix.Project.app_path) |> Mix.Generator.create_directory
existing_migrations = Path.join(Repo.config()[:priv], 'migrations') |> File.ls! |> to_string
unless String.match? existing_migrations, ~r/\d{14}_create_user\.exs/ do
  Mix.Task.run "ecto.gen.migration", ["create_user", "--change", "    create table(:users) do\n      add :email, :string\n      timestamps()\n    end"]
end
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
