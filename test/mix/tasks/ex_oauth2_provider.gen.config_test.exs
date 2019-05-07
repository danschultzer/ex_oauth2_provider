defmodule Mix.Tasks.ExOauth2Provider.Gen.ConfigTest do
  use ExOauth2Provider.Mix.TestCase

  alias Mix.Tasks.ExOauth2Provider.Gen.Config

  defmodule Repo do
    def __adapter__, do: true
    def config, do: [priv: "tmp/#{inspect(Migration)}", otp_app: :ex_oauth2_provider]
  end

  @tmp_path Path.join(["tmp", inspect(Config)])
  @config_file "config/config.exs"
  @options ~w(--context-app test -r #{inspect Repo})

  setup do
    File.rm_rf!(@tmp_path)
    File.mkdir_p!(Path.join(@tmp_path, "config"))

    @tmp_path
    |> Path.join(@config_file)
    |> File.write!(
      """
      use Mix.Config

      if Mix.env() == :test do
        import_config "test.exs"
      end
      """)

    :ok
  end

  test "appends to config file" do
    File.cd!(@tmp_path, fn ->
      original = File.read!(@config_file)

      Config.run(@options)

      file = File.read!(@config_file)

      assert file =~ "config :test, ExOauth2Provider,"
      assert file =~ "  repo: #{inspect Repo},"
      assert file =~ "  resource_owner: Test.Users.User"
      assert file =~ original
    end)
  end

  test "appends only once in config" do
    File.cd!(@tmp_path, fn ->
      # Should only append once
      Config.run(@options)
      file = File.read!(@config_file)
      Config.run(@options)
      file2 = File.read!(@config_file)

      assert file == file2
    end)
  end

  test "configures resource_owner in config file" do
    File.cd!(@tmp_path, fn ->
      Config.run(@options ++ ~w(--resource-owner Test.ResourceOwner))
      file = File.read!(@config_file)

      assert file =~ "  resource_owner: Test.ResourceOwner"
    end)
  end
end
