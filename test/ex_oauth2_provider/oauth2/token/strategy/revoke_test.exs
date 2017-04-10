defmodule ExOauth2Provider.Token.Strategy.RevokeTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Token
  import ExOauth2Provider.Test.Fixture
  import ExOauth2Provider.Test.QueryHelper

  alias ExOauth2Provider.OauthAccessTokens

  @client_id            "Jf5rM8hQBc"
  @client_secret        "secret"
  @invalid_client_error  %{error: :invalid_client,
                           error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                         }

  setup do
    user = fixture(:user)
    application = fixture(:application, user, %{uid: @client_id, secret: @client_secret, scopes: "app:read app:write"})
    access_token = fixture(:access_token, user, %{application: application, use_refresh_token: true, scopes: "app:read"})

    valid_request = %{"client_id" => @client_id,
                      "client_secret" => @client_secret,
                      "token" => access_token.token}
    {:ok, %{access_token: access_token, valid_request: valid_request}}
  end

  test "#revoke/1 error when invalid client", %{valid_request: valid_request} do
    assert {:error, error, :unprocessable_entity} = revoke(Map.merge(valid_request, %{"client_id" => "invalid"}))
    assert error == @invalid_client_error
  end

  test "#revoke/1 error when invalid secret", %{valid_request: valid_request} do
    assert {:error, error, :unprocessable_entity} = revoke(Map.merge(valid_request, %{"client_secret" => "invalid"}))
    assert error == @invalid_client_error
  end

  test "#revoke/1 when missing token", %{valid_request: valid_request} do
    assert {:ok, %{}} == revoke(Map.delete(valid_request, "token"))
    refute OauthAccessTokens.is_revoked?(get_last_access_token())
  end

  test "#revoke/1 when invalid token", %{valid_request: valid_request} do
    assert {:ok, %{}} == revoke(Map.merge(valid_request, %{"token" => "invalid"}))
    refute OauthAccessTokens.is_revoked?(get_last_access_token())
  end

  test "#revoke/1 when access token owned by another client", %{valid_request: valid_request, access_token: access_token} do
    new_application = fixture(:application, fixture(:user), %{uid: "new_app"})
    changeset = Ecto.Changeset.change access_token, application_id: new_application.id
    ExOauth2Provider.repo.update! changeset

    assert {:error, error, :unprocessable_entity} = revoke(Map.merge(valid_request, %{"client_secret" => "invalid"}))
    assert error == @invalid_client_error
  end

  test "#revoke/1 when access token not owned by a client", %{access_token: access_token} do
    changeset = Ecto.Changeset.change access_token, application_id: nil
    ExOauth2Provider.repo.update! changeset

    assert {:ok, %{}} == revoke(%{"token" => access_token.token})
    assert OauthAccessTokens.is_revoked?(get_last_access_token())
  end

  test "#revoke/1", %{valid_request: valid_request} do
    assert {:ok, %{}} == revoke(valid_request)
    assert OauthAccessTokens.is_revoked?(get_last_access_token())
  end
end
