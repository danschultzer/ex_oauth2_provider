defmodule Mix.Tasks.ExOauth2Provider.InstallTest do
  use ExOauth2Provider.Mix.TestCase

  alias Mix.Tasks.ExOauth2Provider.Install
  alias Dummy.Repo

  @tmp_path Path.join(["tmp", inspect(Install)])
  @options ~w(--context-app test -r #{inspect Repo} --no-migration --no-scehmas)

  setup do
    File.rm_rf!(@tmp_path)
    File.mkdir_p!(@tmp_path)

    :ok
  end

  test "prints instructions" do
    File.cd!(@tmp_path, fn ->
      Install.run(@options)

      assert_received {:mix_shell, :info, ["ExOauth2Provider has been installed! Please append the following to `config/config.ex`:" <> msg]}

      assert msg =~ "config :test, ExOauth2Provider,"
      assert msg =~ "  repo: #{inspect Repo},"
      assert msg =~ "  resource_owner: Test.Users.User"
    end)
  end
end
