defmodule ExOauth2Provider.Authorization.GrantTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Authorization.Grant

  import ExOauth2Provider.Factory
  import Ecto.Query

  @client_id          "Jf5rM8hQBc"
  @client_secret      "secret"
  @code               "code"
  @redirect_uri       "urn:ietf:wg:oauth:2.0:oob"
  @valid_request      %{"client_id" => @client_id,
                        "client_secret" => @client_secret,
                        "code" => @code,
                        "grant_type" => "authorization_code",
                        "redirect_uri" => @redirect_uri}

  @invalid_client_error %{error: :invalid_client,
                          error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                        }
  @invalid_grant        %{error: :invalid_grant,
                          error_description: "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
                        }
  @invalid_grant_type  %{error: :unsupported_grant_type,
                          error_description: "The authorization grant type is not supported by the authorization server."
                        }

  def get_last_access_token do
    ExOauth2Provider.repo.one(from x in ExOauth2Provider.OauthAccessTokens.OauthAccessToken,
      order_by: [desc: x.id], limit: 1)
  end

  def fixture(:application) do
    insert(:application, %{uid: @client_id, secret: @client_secret, resource_owner_id: 0})
  end

  def fixture(:resource_owner) do
    insert(:user)
  end

  def fixture(:access_grant, application, user) do
    insert(:access_grant, %{application_id: application.id, resource_owner_id: user.id, token: @code, scopes: "read", redirect_uri: @redirect_uri})
  end

  setup do
    user = fixture(:resource_owner)
    application = fixture(:application)
    access_grant = fixture(:access_grant, application, user)
    {:ok, %{user: user, application: application, access_grant: access_grant}}
  end

  test "#authorize/1 returns access token", %{user: user, application: application, access_grant: access_grant} do
    assert {:ok, access_token} = authorize(@valid_request)
    assert access_token.access_token == get_last_access_token().token
    assert get_last_access_token().resource_owner_id == user.id
    assert get_last_access_token().application_id == application.id
    assert get_last_access_token().scopes == access_grant.scopes
  end

  test "#authorize/1 error when invalid client" do
    request_invalid_client = Map.merge(@valid_request, %{"client_id" => "invalid"})
    assert {:error, error, :unprocessable_entity} = authorize(request_invalid_client)
    assert error == @invalid_client_error
  end

  test "#authorize/1 error when invalid secret" do
    request_invalid_client = Map.merge(@valid_request, %{"client_secret" => "invalid"})
    assert {:error, error, :unprocessable_entity} = authorize(request_invalid_client)
    assert error == @invalid_client_error
  end

  test "#authorize/1 error when invalid grant" do
    request_invalid_grant = Map.merge(@valid_request, %{"code" => "invalid"})
    assert {:error, error, :unprocessable_entity} = authorize(request_invalid_grant)
    assert error == @invalid_grant
  end

  test "#authorize/1 error when grant owned by another client", %{access_grant: access_grant} do
    new_application = insert(:application, %{uid: "new_app", resource_owner_id: 0})
    changeset = Ecto.Changeset.change access_grant, application_id: new_application.id
    ExOauth2Provider.repo.update! changeset

    assert {:error, error, :unprocessable_entity} = authorize(@valid_request)
    assert error == @invalid_grant
  end

  test "#authorize/1 error when grant expired", %{access_grant: access_grant} do
    inserted_at = NaiveDateTime.utc_now |> NaiveDateTime.add(-access_grant.expires_in, :second)
    access_grant
    |> Ecto.Changeset.change(%{inserted_at: inserted_at})
    |> ExOauth2Provider.repo.update()

    assert {:error, error, :unprocessable_entity} = authorize(@valid_request)
    assert error == @invalid_grant
  end

  test "#authorize/1 error when grant revoked", %{access_grant: access_grant} do
    ExOauth2Provider.OauthAccessGrants.revoke(access_grant)

    assert {:error, error, :unprocessable_entity} = authorize(@valid_request)
    assert error == @invalid_grant
  end

  test "#authorize/1 error when invalid grant_type" do
    request_invalid_grant_type = Map.merge(@valid_request, %{"grant_type" => "invalid"})
    assert {:error, error, :unprocessable_entity} = authorize(request_invalid_grant_type)
    assert error == @invalid_grant_type
  end

  test "#authorize/1 error when invalid redirect_uri" do
    request_invalid_redirect_uri = Map.merge(@valid_request, %{"redirect_uri" => "invalid"})
    assert {:error, error, :unprocessable_entity} = authorize(request_invalid_redirect_uri)
    assert error == @invalid_grant
  end
end
