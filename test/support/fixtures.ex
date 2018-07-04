defmodule ExOauth2Provider.Test.Fixtures do
  @moduledoc false

  alias ExOauth2Provider.Test.Repo
  alias ExOauth2Provider.{OauthApplications.OauthApplication, OauthAccessGrants.OauthAccessGrant, OauthAccessTokens}

  @resource_owner ExOauth2Provider.Config.resource_owner_struct(:module)

  def resource_owner(attrs \\ %{}) do
    %@resource_owner{}
    |> Map.merge(%{email: "foo@example.com"})
    |> Map.merge(attrs)
    |> Repo.insert!()
  end

  def application(user, attrs \\ %{}) do
    %OauthApplication{}
    |> Map.merge(%{uid: "test",
                   secret: "secret",
                   name: "OAuth Application",
                   redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
                   scopes: "public read write"})
    |> Map.merge(attrs)
    |> Map.merge(%{owner_id: user.id})
    |> Repo.insert!()
  end

  def access_token(resource_owner, params \\ %{}) do
    {:ok, access_token} = OauthAccessTokens.create_token(resource_owner, params)

    access_token
  end

  def access_grant(application, user, code, redirect_uri) do
    %OauthAccessGrant{}
    |> Map.merge(%{expires_in: 900,
                   redirect_uri: "urn:ietf:wg:oauth:2.0:oob"})
    |> Map.merge(%{application_id: application.id,
                   resource_owner_id: user.id,
                   token: code,
                   scopes: "read",
                   redirect_uri: redirect_uri})
    |> Repo.insert!()
  end

  @doc false
  def start_link do
    Agent.start_link(fn -> Map.new end, name: __MODULE__)
  end
end
