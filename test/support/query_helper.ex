defmodule ExOauth2Provider.Test.QueryHelper do
  @moduledoc false

  import Ecto.Query

  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant
  alias ExOauth2Provider.OauthAccessTokens.OauthAccessToken

  def get_access_grant_by_code(code),
    do: ExOauth2Provider.repo.get_by!(OauthAccessGrant, token: code)

  def get_access_token_by_token(token),
    do: ExOauth2Provider.repo().get_by!(OauthAccessToken, token: token)

  def get_last_access_grant do
    ExOauth2Provider.repo.one(from x in OauthAccessGrant,
      order_by: [desc: x.id], limit: 1)
  end

  def get_last_access_token do
    ExOauth2Provider.repo.one(from x in OauthAccessToken,
      order_by: [desc: x.id], limit: 1)
  end

  def set_application_redirect_uri(application, uri) do
    changeset = Ecto.Changeset.change application, redirect_uri: uri
    ExOauth2Provider.repo.update! changeset
  end

  def set_application_scopes(application, scopes) do
    changeset = Ecto.Changeset.change application, scopes: scopes
    ExOauth2Provider.repo.update! changeset
  end

  def set_access_token_scopes(access_token, scopes) do
    changeset = Ecto.Changeset.change access_token, scopes: scopes
    ExOauth2Provider.repo.update! changeset
  end

  def update_access_token_inserted_at(access_token, amount, units \\ :second) do
    inserted_at = access_token.inserted_at |> NaiveDateTime.add(amount, units)

    access_token
    |> Ecto.Changeset.change(inserted_at: inserted_at)
    |> ExOauth2Provider.repo.update!()
  end
end
