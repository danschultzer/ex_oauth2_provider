defmodule Mix.Tasks.ExOauth2Provider.InstallTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.ExOauth2Provider.Install
  alias ExOauth2Provider.Test.FileHelpers
  alias Mix.Tasks.Ecto.Gen.Migration

  defmodule Repo do
    def __adapter__ do
      true
    end

    def config do
      [priv: "tmp/#{inspect(ExOauth2Provider.Install)}", otp_app: :ex_oauth2_provider]
    end
  end

  @root_tmp_path         Path.join(FileHelpers.tmp_path(), inspect(ExOauth2Provider.Install))
  @migrations_path       Path.join(@root_tmp_path, "migrations")
  @options               ["-r", to_string(Repo), "--no-config"]
  @config_file           Path.join(@root_tmp_path, "config.exs")
  @options_with_config   ["-r", to_string(Repo), "--config-file", @config_file]

  setup do
    File.rm_rf!(@root_tmp_path)
    File.mkdir_p!(@root_tmp_path)
    :ok
  end

  test "generates migrations" do
    Install.run(@options)

    assert [migration_file] = File.ls!(@migrations_path)
    assert String.match?(migration_file, ~r/^\d{14}_create_oauth_tables\.exs$/)
    FileHelpers.assert_file Path.join(@migrations_path, migration_file), fn file ->
      assert file =~ "defmodule Mix.Tasks.ExOauth2Provider.InstallTest.Repo.Migrations.CreateOauthTables do"
      assert file =~ "use Ecto.Migration"
      assert file =~ "def change do"
      assert file =~ "add :owner_id,          :integer, null: false"
      assert file =~ "add :resource_owner_id,      :integer"
      refute file =~ "add :owner_id,          :uuid,    null: false"
      refute file =~ "add :resource_owner_id,      :uuid"
      refute file =~ ":oauth_applications, primary_key: false"
      refute file =~ ":oauth_access_grants, primary_key: false"
      refute file =~ ":oauth_access_tokens, primary_key: false"
      refute file =~ "add :id,                     :uuid,           primary_key: true"
      refute file =~ "add :id,                :uuid,    primary_key: true"
      refute file =~ "add :id,                     :uuid,           primary_key: true"
      refute file =~ "add :application_id,         references(:oauth_applications, type: :uuid)"
    end
  end

  test "generates migrations with uuid for resource_owners" do
    Install.run(@options ++ ~w(--uuid resource_owners))

    assert [migration_file] = File.ls!(@migrations_path)
    FileHelpers.assert_file Path.join(@migrations_path, migration_file), fn file ->
      refute file =~ "add :owner_id,          :integer, null: false"
      refute file =~ "add :resource_owner_id,      :integer"
      assert file =~ "add :owner_id,          :uuid,    null: false"
      assert file =~ "add :resource_owner_id,      :uuid"
      refute file =~ ":oauth_applications, primary_key: false"
      refute file =~ ":oauth_access_grants, primary_key: false"
      refute file =~ ":oauth_access_tokens, primary_key: false"
      refute file =~ "add :id,                     :uuid,           primary_key: true"
      refute file =~ "add :id,                :uuid,    primary_key: true"
      refute file =~ "add :id,                     :uuid,           primary_key: true"
      refute file =~ "add :application_id,         references(:oauth_applications, type: :uuid)"
    end
  end

  test "generates migrations with uuid for all" do
    Install.run(@options ++ ~w(--uuid all))

    assert [migration_file] = File.ls!(@migrations_path)
    FileHelpers.assert_file Path.join(@migrations_path, migration_file), fn file ->
      refute file =~ "add :owner_id,          :integer, null: false"
      refute file =~ "add :resource_owner_id,      :integer"
      assert file =~ "add :owner_id,          :uuid,    null: false"
      assert file =~ "add :resource_owner_id,      :uuid"
      assert file =~ ":oauth_applications, primary_key: false"
      assert file =~ ":oauth_access_grants, primary_key: false"
      assert file =~ ":oauth_access_tokens, primary_key: false"
      assert file =~ "add :id,                     :uuid,           primary_key: true"
      assert file =~ "add :id,                :uuid,    primary_key: true"
      assert file =~ "add :id,                     :uuid,           primary_key: true"
      assert file =~ "add :application_id,         references(:oauth_applications, type: :uuid)"
    end
  end

  test "doesn't generates migrations" do
    Install.run(@options ++ ~w(--no-migrations))

    refute File.exists?(@migrations_path)
  end

  test "doesn't make duplicate oauth migrations" do
    Install.run(@options)
    Install.run(@options)

    assert [_one] = File.ls!(@migrations_path)
  end

  test "doesn't make duplicate timestamp migrations" do
    Migration.run(["test"] ++ @options)
    Install.run(@options)

    assert [test_migration, migration_file] = @migrations_path |> File.ls!() |> Enum.sort()
    date1 = Regex.run(~r/^(\d{14})_.*\.exs$/, test_migration)
    date2 = Regex.run(~r/^(\d{14})_create_oauth_tables\.exs$/, migration_file)
    assert date1 < date2
  end

  test "appends to config file" do
    reset_config_file()

    original = File.read!(@config_file)
    expected = "config :ex_oauth2_provider, ExOauth2Provider"
    Install.run @options_with_config
    source = File.read!(@config_file)

    assert String.starts_with?(source, original)
    assert String.contains?(source, expected)
  end

  test "doesn't append to config file" do
    reset_config_file()

    original = File.read!(@config_file)
    Install.run @options_with_config ++ ~w(--no-config)
    source = File.read!(@config_file)

    assert source == original
  end

  test "appends only once in config" do
    reset_config_file()

    # Should only append once
    Install.run(@options_with_config)
    source = File.read!(@config_file)
    Install.run(@options_with_config)
    source2 = File.read!(@config_file)

    assert source == source2
  end

  test "configures resource_owner in config file" do
    reset_config_file()

    expected = "resource_owner: Test.ResourceOwner"
    Install.run(@options_with_config ++ ["--resource-owner", "Test.ResourceOwner"])
    source = File.read!(@config_file)

    assert String.contains?(source, expected)
  end

  defp reset_config_file(string \\ "") do
    File.write!(@config_file,  "use Mix.Config\n\n" <> string, [:write])
  end
end
