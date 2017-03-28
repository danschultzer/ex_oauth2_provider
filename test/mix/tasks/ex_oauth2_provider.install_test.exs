defmodule Mix.Tasks.ExOauth2Provider.InstallTest do
  use ExUnit.Case, async: true

  import Mix.Tasks.ExOauth2Provider.Install, only: [run: 1]
  import ExOauth2Provider.FileHelpers

  defmodule Repo do
    def __adapter__ do
      true
    end

    def config do
      [priv: "tmp/#{inspect(ExOauth2Provider.Install)}", otp_app: :ex_oauth2_provider]
    end
  end

  tmp_path = Path.join(tmp_path(), inspect(ExOauth2Provider.Install))
  @migrations_path       Path.join(tmp_path, "migrations")
  @options               ["-r", to_string(Repo)]
  @config_file           "tmp/config.exs"
  @options_with_config   @options ++ ["--config-file", @config_file]

  defp reset_config_file(string \\ "") do
    File.write!(@config_file,  "use Mix.Config\n\n" <> string, [:write])
  end

  setup do
    File.rm_rf!(unquote(tmp_path))
    :ok
  end

  test "generates migrations" do
    run @options
    assert [name] = File.ls!(@migrations_path)
    assert String.match? name, ~r/^\d{14}_create_oauth_tables\.exs$/
    assert_file Path.join(@migrations_path, name), fn file ->
      assert file =~ "defmodule Mix.Tasks.ExOauth2Provider.InstallTest.Repo.Migrations.CreateOauthTables do"
      assert file =~ "use Ecto.Migration"
      assert file =~ "def change do"
    end
  end

  test "doesn't generates migrations" do
    run @options ++ ~w(--no-migrations)
    refute File.exists?(@migrations_path)
  end

  test "doesn't make duplicate oauth migrations" do
    run @options
    run @options
    assert [], File.ls!(@migrations_path)
  end

  test "doesn't make duplicate timestamp migrations" do
    Mix.Tasks.Ecto.Gen.Migration.run ["test"] ++ @options
    run @options
    assert [test_migration, name] = File.ls!(@migrations_path)
    date1 = Regex.run(~r/^(\d{14})_.*\.exs$/, test_migration)
    date2 = Regex.run(~r/^(\d{14})_create_oauth_tables\.exs$/, name)
    assert date1 < date2
  end

  test "appends to config file" do
    reset_config_file()
    original = File.read!(@config_file)
    expected = "config :ex_oauth2_provider, ExOauth2Provider"

    run @options_with_config
    source = File.read!(@config_file)
    assert String.starts_with? source, original
    assert String.contains? source, expected
  end

  test "doesn't append to config file" do
    reset_config_file()
    original = File.read!(@config_file)

    run @options ++ ~w(--no-config)
    source = File.read!(@config_file)
    assert source == original
  end

  test "appends only once in config" do
    reset_config_file()

    # Should only append once
    run @options_with_config
    source = File.read!(@config_file)
    run @options_with_config
    source2 = File.read!(@config_file)
    assert source == source2
  end

  test "configures resource_owner in config file" do
    reset_config_file()
    expected = "resource_owner: Test.ResourceOwner"

    run @options_with_config ++ ["--resource-owner", "Test.ResourceOwner"]
    source = File.read!(@config_file)
    assert String.contains? source, expected
  end
end
