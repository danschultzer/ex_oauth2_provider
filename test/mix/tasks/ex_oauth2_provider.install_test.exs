defmodule Mix.Tasks.ExOauth2Provider.InstallTest do
  use ExUnit.Case, async: true

  import Mix.Tasks.ExOauth2Provider.Install, only: [run: 1]
  import ExOauth2Provider.FileHelpers

  tmp_path = Path.join(tmp_path(), inspect(ExOauth2Provider.Install))
  @migrations_path Path.join(tmp_path, "migrations")

  defmodule Repo do
    def __adapter__ do
      true
    end

    def config do
      [priv: "tmp/#{inspect(ExOauth2Provider.Install)}", otp_app: :ex_oauth2_provider]
    end
  end

  setup do
    File.rm_rf!(unquote(tmp_path))
    :ok
  end

  test "generates migrations" do
    run ["-r", to_string(Repo)]
    assert [name] = File.ls!(@migrations_path)
    assert String.match? name, ~r/^\d{14}_create_oauth_tables\.exs$/
    assert_file Path.join(@migrations_path, name), fn file ->
      assert file =~ "defmodule Mix.Tasks.ExOauth2Provider.InstallTest.Repo.Migrations.CreateOauthTables do"
      assert file =~ "use Ecto.Migration"
      assert file =~ "def change do"
    end
  end

  test "doesn't make duplicate oauth migrations" do
    run ["-r", to_string(Repo)]
    run ["-r", to_string(Repo)]
    assert [], File.ls!(@migrations_path)
  end

  test "doesn't make duplicate timestamp migrations" do
    Mix.Tasks.Ecto.Gen.Migration.run ["test", "-r", to_string(Repo)]
    run ["-r", to_string(Repo)]
    assert [test_migration, name] = File.ls!(@migrations_path)
    date1 = Regex.run(~r/^(\d{14})_.*\.exs$/, test_migration)
    date2 = Regex.run(~r/^(\d{14})_create_oauth_tables\.exs$/, name)
    assert date1 < date2
  end
end
