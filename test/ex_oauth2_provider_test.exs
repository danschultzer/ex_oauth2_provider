defmodule ExOauth2ProviderTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Factory
  import ExOauth2Provider
  alias ExOauth2Provider.OauthAccessToken
  alias ExOauth2Provider.Test.Repo

  test "it authenticates with token" do
    user = insert(:user)
    attrs = params_for(:access_token, %{resource_owner_id: user.id})
    {_, access_token} = Repo.insert(OauthAccessToken.create_changeset(%OauthAccessToken{}, attrs))
    assert authenticate_token(access_token.token) == {:ok, Repo.get!(OauthAccessToken, access_token.id)}
  end

  test "it rejects inaccessible token" do
    user = insert(:user)

    # Inserting and changing inserted_at timestamp
    attrs = params_for(:access_token, %{resource_owner_id: user.id, expires_in: 1})
    {_, access_token} = Repo.insert(OauthAccessToken.create_changeset(%OauthAccessToken{}, attrs))
    inserted_at = :os.system_time(:microsecond) - 2 * :math.pow(10,6)
      |> round
      |> DateTime.from_unix!(:microsecond)
      |> Ecto.DateTime.cast!
    access_token = Ecto.Changeset.change(access_token, inserted_at: inserted_at)
      |> Repo.update!
    assert authenticate_token(access_token.token) == {:error, :token_inaccessible}

    attrs = params_for(:access_token, %{resource_owner_id: user.id, revoked_at: NaiveDateTime.utc_now})
    {_, access_token} = Repo.insert(OauthAccessToken.create_changeset(%OauthAccessToken{}, attrs))
    assert authenticate_token(access_token.token) == {:error, :token_inaccessible}
  end

  test "it generate random token" do
    assert generate_token() != generate_token()
  end

  test "it generate the token with custom length" do
    assert String.length(generate_token(%{size: 1})) < String.length(generate_token(%{size: 2}))
  end

  test "it generate the token with custom generator" do
    generator = fn(string) -> Base.encode64(string) end
    assert String.length(generate_token(%{generator: generator})) < String.length(generate_token())
  end
end
