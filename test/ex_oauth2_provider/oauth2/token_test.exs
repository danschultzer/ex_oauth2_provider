defmodule ExOauth2Provider.TokenTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Token
  import ExOauth2Provider.Test.Fixture

  @client_id          "Jf5rM8hQBc"
  @client_secret      "secret"

  setup do
    application = fixture(:application, fixture(:user), %{})
    {:ok, %{application: application}}
  end

  test "#grant/1 error when invalid grant_type" do
    request_invalid_grant_type = Map.merge(%{"client_id" => @client_id,
                                             "client_secret" => @client_secret,
                                             "grant_type" => "client_credentials"},
                                           %{"grant_type" => "invalid"})
    assert {:error, error, :unprocessable_entity} = grant(request_invalid_grant_type)
    assert error == %{error: :unsupported_grant_type,
                      error_description: "The authorization grant type is not supported by the authorization server."
                    }
  end
end
