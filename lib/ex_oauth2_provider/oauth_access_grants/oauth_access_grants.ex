defmodule ExOauth2Provider.OauthAccessGrants do
  @moduledoc """
  The boundary for the OauthAccessGrants system.
  """

  import Ecto.{Query, Changeset}, warn: false
  use ExOauth2Provider.Mixin.Expirable
  use ExOauth2Provider.Mixin.Revocable
  alias ExOauth2Provider.OauthApplications.OauthApplication
  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant

  @doc """
  Gets a single access grant.

  ## Examples

      iex> get_grant("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d", "jE9dk")
      %OauthAccessGrant{}

      iex> get_grant("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc", "jE9dk")
      ** nil

  """
  def get_grant(%OauthApplication{id: _} = application, token) do
    access_grant = OauthAccessGrant
    |> ExOauth2Provider.repo.get_by(application_id: application.id, token: token)
    |> filter_expired
    |> filter_revoked
  end

  @doc """
  Creates an access grant.

  ## Examples

      iex> create_application(user, app)
      {:ok, %OauthAccessGrant{}}

      iex> create_application(user, invalid_app)
      {:error, %Ecto.Changeset{}}

  """
  def create_grant(%{id: _} = resource_owner, %OauthApplication{id: _} = application, attrs) do
    %OauthAccessGrant{resource_owner: resource_owner, application: application}
    |> new_grant_changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end

  defp new_grant_changeset(%OauthAccessGrant{} = grant, params) do
    grant
    |> cast(params, [:redirect_uri, :expires_in, :scopes])
    |> assoc_constraint(:application)
    |> assoc_constraint(:resource_owner)
    |> put_token
    |> validate_required([:redirect_uri, :expires_in, :token, :resource_owner, :application])
    |> unique_constraint(:token)
  end

  defp put_token(changeset) do
    changeset
    |> put_change(:token, ExOauth2Provider.Utils.generate_token)
  end
end
