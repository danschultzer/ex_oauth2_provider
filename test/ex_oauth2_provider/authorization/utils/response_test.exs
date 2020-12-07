defmodule ExOauth2Provider.Authorization.Utils.ResponseTest do
  use ExUnit.Case
  alias ExOauth2Provider.Authorization.Utils.Response

  test "authorize_response/2 returns native_redirect when do_native_redirect option is provided" do
    assert Response.authorize_response(
             {:ok, %{request: %{"redirect_uri" => ""}, grant: %{token: "asdf123"}}},
             do_native_redirect: true
           ) ==
             {:native_redirect, %{code: "asdf123"}}
  end

  test "authorize_response/2 returns redirect_uri without do_native_redirect option" do
    assert Response.authorize_response(
             {:ok,
              %{
                request: %{"redirect_uri" => "https://example.com"},
                grant: %{
                  token: "asdf123"
                }
              }},
             []
           ) ==
             {:redirect, "https://example.com?code=asdf123"}
  end
end
