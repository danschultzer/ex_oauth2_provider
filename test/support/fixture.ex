defmodule ExOauth2Provider.Test.Fixture do
  @moduledoc false

  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.Test.Repo

  @resource_owner ExOauth2Provider.Config.resource_owner_struct(:module)

  def fixture(:user, attrs \\ %{}) do
    {:ok, user} = %@resource_owner{}
    |> Map.merge(%{email: "foo@example.com"})
    |> Map.merge(attrs)
    |> Repo.insert

    user
  end

  def fixture(:application, user, %{} = attrs) do
    {:ok, application} = %OauthApplications.OauthApplication{}
    |> Map.merge(%{uid: "test",
                   secret: "secret",
                   name: "OAuth Application",
                   redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
                   scopes: "public read write"})
    |> Map.merge(attrs)
    |> Map.merge(%{owner_id: user.id})
    |> Repo.insert

    application
  end

  def fixture(:access_token, resource_owner, %{} = params) do
    {:ok, access_token} = resource_owner
    |> OauthAccessTokens.create_token(params)

    access_token
  end

  def fixture(:access_grant, application, user, code, redirect_uri) do
    {:ok, grant} = %OauthAccessGrants.OauthAccessGrant{}
    |> Map.merge(%{expires_in: 900,
                   redirect_uri: "urn:ietf:wg:oauth:2.0:oob"})
    |> Map.merge(%{application_id: application.id,
                   resource_owner_id: user.id,
                   token: code,
                   scopes: "read",
                   redirect_uri: redirect_uri})
    |> Repo.insert

    grant
  end

  @doc false
  def start_link do
    Agent.start_link(fn -> Map.new end, name: __MODULE__)
  end
end
