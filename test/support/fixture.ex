defmodule ExOauth2Provider.Test.Fixture do
  import ExOauth2Provider.Factory

  def fixture(:user, attrs \\ %{}) do
    insert(:user, attrs)
  end

  def fixture(:application, user, %{} = attrs) do
    insert(:application, Map.merge(attrs, %{resource_owner_id: user.id}))
  end

  def fixture(:access_token, resource_owner, %{} = params) do
    {:ok, access_token} = resource_owner |> ExOauth2Provider.OauthAccessTokens.create_token(params)

    access_token
  end

  def fixture(:access_grant, application, user, code, redirect_uri) do
    insert(:access_grant, %{application_id: application.id,
                            resource_owner_id: user.id,
                            token: code,
                            scopes: "read",
                            redirect_uri: redirect_uri})
  end
end
