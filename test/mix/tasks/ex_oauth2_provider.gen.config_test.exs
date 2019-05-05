defmodule Mix.Tasks.ExOauth2Provider.Gen.ConfigTest do
  use ExOauth2Provider.Mix.TestCase

  alias Mix.Tasks.ExOauth2Provider.Gen.Config

  defmodule Repo do
    def __adapter__, do: true
    def config, do: [priv: "tmp/#{inspect(Migration)}", otp_app: :ex_oauth2_provider]
  end

  @tmp_path Path.join(["tmp", inspect(Config)])
  @config_file "config/config.exs"
  @options ~w(-r #{to_string(Repo)})

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
      expected = "config :ex_oauth2_provider, ExOauth2Provider"
      Config.run(@options)
      source = File.read!(@config_file)

      assert String.starts_with?(source, original)
      assert String.contains?(source, expected)
    end)
  end

  test "appends only once in config" do
    File.cd!(@tmp_path, fn ->
      # Should only append once
      Config.run(@options)
      source = File.read!(@config_file)
      Config.run(@options)
      source2 = File.read!(@config_file)

      assert source == source2
    end)
  end

  test "configures resource_owner in config file" do
    File.cd!(@tmp_path, fn ->
      expected = "resource_owner: Test.ResourceOwner"
      Config.run(@options ++ ~w(--resource-owner Test.ResourceOwner))
      source = File.read!(@config_file)

      assert String.contains?(source, expected)
    end)
  end
end
