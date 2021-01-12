defmodule ExOauth2Provider.TokenTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Token
  alias ExOauth2Provider.Test.Fixtures

  @client_id "Jf5rM8hQBc"
  @client_secret "secret"

  setup do
    application = Fixtures.application()
    {:ok, %{application: application}}
  end

  test "#grant/2 error when invalid grant_type" do
    request_invalid_grant_type =
      Map.merge(
        %{
          "client_id" => @client_id,
          "client_secret" => @client_secret,
          "grant_type" => "client_credentials"
        },
        %{"grant_type" => "invalid"}
      )

    expected_error = %{
      error: :unsupported_grant_type,
      error_description:
        "The authorization grant type is not supported by the authorization server."
    }

    assert Token.grant(request_invalid_grant_type, otp_app: :ex_oauth2_provider) ==
             {:error, expected_error, :unprocessable_entity}
  end

  defmodule CustomGrantType do
    def grant(_request, _config), do: {:ok, "access_token"}
  end

  test "#grant/2 with custom grant_type" do
    assert Token.grant(%{"grant_type" => "my_custom_grant_type"},
             otp_app: :ex_oauth2_provider,
             custom_grant_flows: %{"my_custom_grant_type" => CustomGrantType}
           ) ==
             {:ok, "access_token"}
  end
end
