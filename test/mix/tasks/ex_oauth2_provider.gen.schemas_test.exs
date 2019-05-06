defmodule Mix.Tasks.ExOauth2Provider.Gen.SchemasTest do
  use ExOauth2Provider.Mix.TestCase

  alias Mix.Tasks.ExOauth2Provider.Gen.Schemas

  @tmp_path Path.join(["tmp", inspect(Schemas)])
  @options []
  @files ["access_grant", "access_token", "application"]

  setup do
    File.rm_rf!(@tmp_path)
    File.mkdir_p!(@tmp_path)

    :ok
  end

  test "generates files" do
    File.cd!(@tmp_path, fn ->
      root_path = Path.join(["lib", "ex_oauth2_provider"])

      Schemas.run(@options)

      for file <- @files do
        path = Path.join([root_path, "oauth_#{file}s", "oauth_#{file}.ex"])

        assert File.exists?(path)

        module  = Module.concat(["ExOauth2Provider", Macro.camelize("oauth_#{file}s"), Macro.camelize("oauth_#{file}")])
        macro   = Module.concat(["ExOauth2Provider", Macro.camelize("#{file}s"), Macro.camelize("#{file}")])
        content = File.read!(path)

        assert content =~ "defmodule #{inspect module} do"
        assert content =~ "use #{inspect macro}"
        assert content =~ "#{file}_fields()"
      end
    end)
  end
end
