Logger.configure(level: :warn)

ExUnit.start()

# Ensure that symlink to custom ecto priv directory exists
source = Dummy.Repo.config()[:priv]
target = Application.app_dir(:ex_oauth2_provider, source)
File.rm_rf(target)
File.mkdir_p(target)
File.rmdir(target)
:ok = :file.make_symlink(Path.expand(source), target)

# Set up database
Mix.Task.run("ecto.drop", ~w(--quiet -r Dummy.Repo))
Mix.Task.run("ecto.create", ~w(--quiet -r Dummy.Repo))
Mix.Task.run("ecto.migrate", ~w(-r Dummy.Repo))

{:ok, _pid} = Dummy.Repo.start_link()
Ecto.Adapters.SQL.Sandbox.mode(Dummy.Repo, :manual)
