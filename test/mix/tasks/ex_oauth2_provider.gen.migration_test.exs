defmodule Mix.Tasks.ExOauth2Provider.Gen.MigrationTest do
  use ExOauth2Provider.Mix.TestCase

  alias Mix.Tasks.ExOauth2Provider.Gen.Migration

  defmodule Repo do
    def __adapter__, do: true
    def config, do: [priv: "tmp/#{inspect(Migration)}", otp_app: :ex_oauth2_provider]
  end

  @tmp_path Path.join(["tmp", inspect(Migration)])
  @migrations_path Path.join(@tmp_path, "migrations")
  @options ~w(-r #{inspect Repo})

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

      file = @migrations_path |> Path.join(migration_file) |> File.read!()

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
    end)
  end

  test "generates migrations with binary id" do
    File.cd!(@tmp_path, fn ->
      Migration.run(@options ++ ~w(--binary-id))

      assert [migration_file] = File.ls!(@migrations_path)

      file = @migrations_path |> Path.join(migration_file) |> File.read!()

      refute file =~ "add :owner_id, :integer, null: false"
      refute file =~ "add :resource_owner_id, :integer"
      assert file =~ "add :owner_id, references(:users, on_delete: :nothing, type: :binary_id)"
      assert file =~ "add :resource_owner_id, references(:users, on_delete: :nothing, type: :binary_id)"
      assert file =~ ":oauth_applications, primary_key: false"
      assert file =~ ":oauth_access_grants, primary_key: false"
      assert file =~ ":oauth_access_tokens, primary_key: false"
      assert file =~ "add :id, :binary_id, primary_key: true"
      assert file =~ "add :application_id, references(:oauth_applications, on_delete: :nothing, type: :binary_id)"
    end)
  end

  test "doesn't make duplicate migrations" do
    File.cd!(@tmp_path, fn ->
      Migration.run(@options)

      assert_raise Mix.Error, "migration can't be created, there is already a migration file with name CreateOauthTables.", fn ->
        Migration.run(@options)
      end
    end)
  end
end
