defmodule ExOauth2Provider.ConfigTest do
  use ExUnit.Case
  alias ExOauth2Provider.Config

  setup do
    config = Application.get_env(:ex_oauth2_provider, ExOauth2Provider)

    on_exit(fn ->
      Application.put_env(:ex_oauth2_provider, ExOauth2Provider, config)
    end)
  end

  test "repo/1" do
    assert Config.repo(otp_app: :my_app) == Dummy.Repo

    Application.delete_env(:ex_oauth2_provider, ExOauth2Provider)
    Application.put_env(:my_app, ExOauth2Provider, repo: Dummy.Repo)

    assert Config.repo(otp_app: :my_app) == Dummy.Repo

    Application.delete_env(:my_app, ExOauth2Provider)

    assert_raise RuntimeError, ~r/config :my_app, ExOauth2Provider/, fn ->
      Config.repo(otp_app: :my_app)
    end

    assert_raise RuntimeError, ~r/config :ex_oauth2_provider, ExOauth2Provider/, fn ->
      Config.repo([])
    end
  end
end
