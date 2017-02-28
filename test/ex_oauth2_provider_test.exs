defmodule ExOauth2ProviderTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Factory
  import ExOauth2Provider

  alias ExOauth2Provider.OauthAccessToken
  alias ExOauth2Provider.Test.Repo

  test "it authenticates with token" do
    {_, access_token} = access_token_with_user()

    assert authenticate_token(access_token.token) == {:ok, Repo.get!(OauthAccessToken, access_token.id)}
  end

  test "it rejects expired token" do
    access_token = access_token_with_user(%{expires_in: 1})
      |> elem(1)
      |> update_access_token_inserted_at(-2)

    assert authenticate_token(access_token.token) == {:error, :token_inaccessible}
  end

  test "it rejects revoked token" do
    {_, access_token} = access_token_with_user(%{revoked_at: NaiveDateTime.utc_now})

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
