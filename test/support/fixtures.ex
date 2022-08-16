defmodule ExOauth2Provider.Test.Fixtures do
  @moduledoc false

  alias ExOauth2Provider.AccessTokens
  alias Dummy.{OauthApplications.OauthApplication, OauthAccessGrants.OauthAccessGrant, Repo, Users.User}
  alias Ecto.Changeset

  def resource_owner(attrs \\ []) do
    attrs = Keyword.merge([email: "foo@example.com"], attrs)

    User
    |> struct()
    |> Changeset.change(attrs)
    |> Repo.insert!()
  end

  def application(attrs \\ []) do
    resource_owner = Keyword.get(attrs, :resource_owner) || resource_owner()
    attrs          = [
      owner_id: resource_owner.id,
      uid: "test",
      secret: "secret",
      name: "OAuth Application",
      redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
      scopes: "public read write"]
      |> Keyword.merge(attrs)
      |> Keyword.drop([:resource_owner])

    %OauthApplication{}
    |> Changeset.change(attrs)
    |> Repo.insert!()
  end

  def access_token(attrs \\ []) do
    {:ok, access_token} =
      attrs
      |> Keyword.get(:resource_owner)
      |> Kernel.||(resource_owner())
      |> AccessTokens.create_token(Enum.into(attrs, %{}), otp_app: :ex_oauth2_provider)

    access_token
  end

  def application_access_token(attrs \\ []) do
    {:ok, access_token} =
      attrs
      |> Keyword.get(:application)
      |> Kernel.||(application())
      |> AccessTokens.create_application_token(Enum.into(attrs, %{}), otp_app: :ex_oauth2_provider)

    access_token
  end


  def access_grant(application, user, code, redirect_uri, extra_attrs \\ []) do
    attrs = [
      expires_in: 900,
      redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
      application_id: application.id,
      resource_owner_id: user.id,
      token: code,
      scopes: "read",
      redirect_uri: redirect_uri
    ] ++ extra_attrs

    %OauthAccessGrant{}
    |> Changeset.change(attrs)
    |> Repo.insert!()
  end
end
