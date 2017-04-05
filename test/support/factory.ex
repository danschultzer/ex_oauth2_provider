defmodule ExOauth2Provider.Factory do
  @moduledoc """
  Generates factories
  """

  @repo           ExOauth2Provider.repo()
  @resource_owner ExOauth2Provider.resource_owner_struct()
  @application    ExOauth2Provider.OauthApplications.OauthApplication
  @access_token   ExOauth2Provider.OauthAccessTokens.OauthAccessToken
  @access_grant   ExOauth2Provider.OauthAccessGrants.OauthAccessGrant

  use ExMachina.Ecto, repo: @repo

  def application_factory do
    %@application{
      uid: "test",
      secret: "secret",
      name: "OAuth Application",
      redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
      scopes: "read write"
    }
  end

  def access_token_factory do
    %@access_token{
      token: "secret",
      scopes: "read write"
    }
  end

  def access_grant_factory do
    %@access_grant{
      expires_in: 900,
      redirect_uri: "urn:ietf:wg:oauth:2.0:oob"
    }
  end

  def user_factory do
    %@resource_owner{
      email: sequence(:email, &"foo-#{&1}@example.com")
    }
  end

  def access_token_with_user(params \\ %{}) do
    {:ok, access_token} = :user
    |> insert
    |> ExOauth2Provider.OauthAccessTokens.create_token(params)

    access_token
  end

  def update_access_token_inserted_at(access_token, amount, units \\ :second) do
    inserted_at = access_token.inserted_at |> NaiveDateTime.add(amount, units)
    Ecto.Changeset.change(access_token, inserted_at: inserted_at)
      |> @repo.update!
  end
end
