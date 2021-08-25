defmodule Mix.Tasks.ExOauth2Provider.Gen.SchemasTest do
  use ExOauth2Provider.Mix.TestCase

  alias Mix.Tasks.ExOauth2Provider.Gen.Schemas

  @tmp_path Path.join(["tmp", inspect(Schemas)])
  @options ~w(--context-app test)
  @required_files ~w(access_grant access_token application)
  @optional_files ~w(device_grant)

  setup do
    File.rm_rf!(@tmp_path)
    File.mkdir_p!(@tmp_path)

    :ok
  end

  test "generates files" do
    File.cd!(@tmp_path, fn ->
      root_path = Path.join(["lib", "test"])

      Schemas.run(@options)

      for file <- @required_files do
        path = Path.join([root_path, "oauth_#{file}s", "oauth_#{file}.ex"])

        assert File.exists?(path)

        module = modulize(file)
        macro = macroize(file)
        content = File.read!(path)

        assert content =~ "defmodule #{inspect(module)} do"
        assert content =~ "use #{inspect(macro)}, otp_app: :test"
        assert content =~ "schema \"oauth_#{file}s\" do"
        assert content =~ "#{file}_fields()"
      end

      for file <- @optional_files do
        path = Path.join([root_path, "oauth_#{file}s", "oauth_#{file}.ex"])

        refute File.exists?(path)
      end
    end)
  end

  test "it uses the configured otp_app when --context-app is not given" do
    File.cd!(@tmp_path, fn ->
      # Test config defines :ex_oauth2_provider as the otp_app
      root_path = Path.join(["lib", "ex_oauth2_provider"])

      Schemas.run([])

      for file <- @required_files do
        path = Path.join([root_path, "oauth_#{file}s", "oauth_#{file}.ex"])

        assert File.exists?(path)

        macro = macroize(file)

        assert File.read!(path) =~ "use #{inspect(macro)}, otp_app: :ex_oauth2_provider"
      end
    end)
  end

  test "it creates the device_grant schema when config has device_code grant flow" do
    File.cd!(@tmp_path, fn ->
      root_path = Path.join(["lib", "test"])

      @options
      |> Enum.concat(~w(--device-code))
      |> Schemas.run()

      for file <- @required_files do
        path = Path.join([root_path, "oauth_#{file}s", "oauth_#{file}.ex"])

        assert File.exists?(path)
      end

      for file <- @optional_files do
        path = Path.join([root_path, "oauth_#{file}s", "oauth_#{file}.ex"])

        assert File.exists?(path)

        module = modulize(file)
        macro = macroize(file)
        content = File.read!(path)

        assert content =~ "defmodule #{inspect(module)} do"
        assert content =~ "use #{inspect(macro)}, otp_app: :test"
        assert content =~ "schema \"oauth_#{file}s\" do"
        assert content =~ "#{file}_fields()"
      end
    end)
  end

  defp modulize(file) do
    Module.concat([
      "Test",
      Macro.camelize("oauth_#{file}s"),
      Macro.camelize("oauth_#{file}")
    ])
  end

  defp macroize(file) do
    Module.concat([
      "ExOauth2Provider",
      Macro.camelize("#{file}s"),
      Macro.camelize("#{file}")
    ])
  end
end
