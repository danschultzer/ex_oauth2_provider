defmodule ExOauth2ProviderTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Factory
  import ExOauth2Provider

  alias ExOauth2Provider.Test.Repo

  test "it rejects" do
    assert authenticate_token("secret") == {:error, :token_not_found}
  end

  test "it authenticates" do
    access_token = access_token_with_user()

    assert authenticate_token(access_token.token) == {:ok, access_token}
  end

  test "it rejects expired token" do
    access_token = access_token_with_user(%{expires_in: 1})
      |> update_access_token_inserted_at(-2)

    assert authenticate_token(access_token.token) == {:error, :token_inaccessible}
  end

  test "it rejects revoked token" do
    access_token = access_token_with_user()
    ExOauth2Provider.OauthAccessTokens.revoke(access_token)

    assert authenticate_token(access_token.token) == {:error, :token_inaccessible}
  end

  test "it reject with no resource" do
    access_token = access_token_with_user()
    |> Ecto.Changeset.change(resource_owner_id: 0)
    |> Repo.update!

    assert authenticate_token(access_token.token) == {:error, :no_association_found}
  end
end
