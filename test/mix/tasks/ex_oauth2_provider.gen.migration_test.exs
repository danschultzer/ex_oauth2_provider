defmodule Mix.Tasks.ExOauth2Provider.Gen.MigrationTest do
  use ExOauth2Provider.Mix.TestCase

  alias Mix.Tasks.ExOauth2Provider.Gen.Migration

  defmodule Repo do
    def __adapter__, do: true
    def config, do: [priv: "tmp/#{inspect(Migration)}", otp_app: :ex_oauth2_provider]
  end

  @tmp_path Path.join(["tmp", inspect(Migration)])
  @options ~w(-r #{to_string(Repo)})
  @migrations_path Path.join(@tmp_path, "migrations")

  setup do
    File.rm_rf!(@tmp_path)
    File.mkdir_p!(@tmp_path)
    :ok
  end

  test "generates migrations" do
    File.cd!(@tmp_path, fn ->
      Migration.run(@options)

      assert [migration_file] = File.ls!(@migrations_path)
      assert String.match?(migration_file, ~r/^\d{14}_create_oauth_tables\.exs$/)
      assert_file Path.join(@migrations_path, migration_file), fn file ->
        assert file =~ "defmodule #{inspect Repo}.Migrations.CreateOauthTables do"
        assert file =~ "use Ecto.Migration"
        assert file =~ "def change do"
        assert file =~ "add :owner_id, references(:users, on_delete: :nothing)"
        assert file =~ "add :resource_owner_id, references(:users, on_delete: :nothing)"
        refute file =~ "add :owner_id, references(:users, on_delete: :nothing, type: :binary_id)"
        refute file =~ "add :resource_owner_id, references(:users, on_delete: :nothing, type: :binary_id)"
        refute file =~ ":oauth_applications, primary_key: false"
        refute file =~ ":oauth_access_grants, primary_key: false"
        refute file =~ ":oauth_access_tokens, primary_key: false"
        refute file =~ "add :id, :binary_id, primary_key: true"
        refute file =~ "add :application_id, references(:oauth_applications, on_delete: :nothing, type: binary_id)"
      end
    end)
  end

  test "generates migrations with binary id" do
    File.cd!(@tmp_path, fn ->
      Migration.run(@options ++ ~w(--binary-id))

      assert [migration_file] = File.ls!(@migrations_path)
      assert_file Path.join(@migrations_path, migration_file), fn file ->
        refute file =~ "add :owner_id, :integer, null: false"
        refute file =~ "add :resource_owner_id, :integer"
        assert file =~ "add :owner_id, references(:users, on_delete: :nothing, type: :binary_id)"
        assert file =~ "add :resource_owner_id, references(:users, on_delete: :nothing, type: :binary_id)"
        assert file =~ ":oauth_applications, primary_key: false"
        assert file =~ ":oauth_access_grants, primary_key: false"
        assert file =~ ":oauth_access_tokens, primary_key: false"
        assert file =~ "add :id, :binary_id, primary_key: true"
        assert file =~ "add :application_id, references(:oauth_applications, on_delete: :nothing, type: :binary_id)"
      end
    end)
  end

  test "doesn't make duplicate timestamp migrations" do
    File.cd!(@tmp_path, fn ->
      Mix.Tasks.Ecto.Gen.Migration.run(["test", "-r", to_string(Repo)])
      Migration.run(@options)

      assert [test_migration, migration_file] = @migrations_path |> File.ls!() |> Enum.sort()
      date1 = Regex.run(~r/^(\d{14})_.*\.exs$/, test_migration)
      date2 = Regex.run(~r/^(\d{14})_create_oauth_tables\.exs$/, migration_file)
      assert date1 < date2
    end)
  end

  defp assert_file(file) do
    assert File.regular?(file), "Expected #{file} to exist, but does not"
  end

  defp assert_file(file, callback) when is_function(callback, 1) do
    assert_file(file)
    callback.(File.read!(file))
  end
end
