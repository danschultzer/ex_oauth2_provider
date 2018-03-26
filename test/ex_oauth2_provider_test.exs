defmodule ExOauth2ProviderTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Test.Fixture
  import ExOauth2Provider.Test.QueryHelper
  import ExOauth2Provider.ConfigHelpers
  import ExOauth2Provider

  test "authenticate_token/1 error when invalid" do
    assert authenticate_token(nil) == {:error, :token_inaccessible}
    assert authenticate_token("secret") == {:error, :token_not_found}
  end

  test "authenticate_token/1 authenticates" do
    access_token = fixture(:access_token, fixture(:user), %{})

    assert authenticate_token(access_token.token) == {:ok, access_token}
  end

  test "authenticate_token/1 revokes previous refresh token" do
    user = fixture(:user)
    access_token  = fixture(:access_token, user, %{use_refresh_token: true})
    access_token2 = fixture(:access_token, user, %{use_refresh_token: true, previous_refresh_token: access_token})

    assert {:ok, access_token} = authenticate_token(access_token.token)
    access_token = ExOauth2Provider.repo.get_by(ExOauth2Provider.OauthAccessTokens.OauthAccessToken, token: access_token.token)
    refute ExOauth2Provider.OauthAccessTokens.is_revoked?(access_token)
    access_token2 = ExOauth2Provider.repo.get_by(ExOauth2Provider.OauthAccessTokens.OauthAccessToken, token: access_token2.token)
    refute "" == access_token2.previous_refresh_token

    assert {:ok, access_token2} = authenticate_token(access_token2.token)
    access_token = ExOauth2Provider.repo.get_by(ExOauth2Provider.OauthAccessTokens.OauthAccessToken, token: access_token.token)
    assert ExOauth2Provider.OauthAccessTokens.is_revoked?(access_token)
    access_token2 = ExOauth2Provider.repo.get_by(ExOauth2Provider.OauthAccessTokens.OauthAccessToken, token: access_token2.token)
    assert "" == access_token2.previous_refresh_token
  end

  test "authenticate_token/1 doesn't revoke when refresh_token_revoked_on_use? == false" do
    set_config(:revoke_refresh_token_on_use, false)

    user = fixture(:user)
    access_token  = fixture(:access_token, user, %{use_refresh_token: true})
    access_token2 = fixture(:access_token, user, %{use_refresh_token: true, previous_refresh_token: access_token})

    assert {:ok, access_token2} = authenticate_token(access_token2.token)
    access_token = ExOauth2Provider.repo.get_by(ExOauth2Provider.OauthAccessTokens.OauthAccessToken, token: access_token.token)
    refute ExOauth2Provider.OauthAccessTokens.is_revoked?(access_token)
    access_token2 = ExOauth2Provider.repo.get_by(ExOauth2Provider.OauthAccessTokens.OauthAccessToken, token: access_token2.token)
    refute "" == access_token2.previous_refresh_token
  end

  test "authenticate_token/1 error when expired token" do
    access_token = :access_token
    |> fixture(fixture(:user), %{expires_in: 1})
    |> update_access_token_inserted_at(-2)

    assert authenticate_token(access_token.token) == {:error, :token_inaccessible}
  end

  test "authenticate_token/1 error when revoked token" do
    access_token = fixture(:access_token, fixture(:user), %{})
    ExOauth2Provider.OauthAccessTokens.revoke(access_token)

    assert authenticate_token(access_token.token) == {:error, :token_inaccessible}
  end

  test "authenticate_token/1 error when no resource owner" do
    resource_owner_id = (if is_nil(System.get_env("UUID")), do: 0, else: "09b58e2b-8fff-4b8d-ba94-18a06dd4fc29")

    access_token = fixture(:access_token, fixture(:user), %{})
    |> Ecto.Changeset.change(resource_owner_id: resource_owner_id)
    |> ExOauth2Provider.repo.update!

    assert authenticate_token(access_token.token) == {:error, :no_association_found}
  end
end
