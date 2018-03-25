defmodule ExOauth2Provider.OauthAccessGrants do
  @moduledoc """
  The boundary for the OauthAccessGrants system.
  """

  import Ecto.{Query, Changeset}, warn: false
  use ExOauth2Provider.Mixin.Expirable
  use ExOauth2Provider.Mixin.Revocable
  use ExOauth2Provider.Mixin.Scopes
  alias ExOauth2Provider.OauthApplications.OauthApplication
  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant

  @doc """
  Gets a single access grant registered with an application.

  ## Examples

      iex> get_active_grant_for(application, "jE9dk")
      %OauthAccessGrant{}

      iex> get_active_grant_for(application, "jE9dk")
      ** nil

  """
  @spec get_active_grant_for(%OauthApplication{}, String.t) :: %OauthAccessGrant{} | nil
  def get_active_grant_for(application, token) do
    clauses = OauthAccessGrant
    |> ExOauth2Provider.Utils.belongs_to_clause(:application, application)
    |> Keyword.put(:token, token)

    OauthAccessGrant
    |> ExOauth2Provider.repo.get_by(clauses)
    |> filter_expired()
    |> filter_revoked()
  end

  @doc """
  Creates an access grant.

  ## Examples

      iex> create_grant(resource_owner, application, attrs)
      {:ok, %OauthAccessGrant{}}

      iex> create_grant(resource_owner, application, attrs)
      {:error, %Ecto.Changeset{}}

  """
  @spec create_grant(Ecto.Schema.t, %OauthApplication{}, Map.t) :: {:ok, %OauthAccessGrant{}} | {:error, term}
  def create_grant(resource_owner, application, attrs) do
    %OauthAccessGrant{resource_owner: resource_owner, application: application}
    |> new_grant_changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end

  defp new_grant_changeset(%OauthAccessGrant{} = grant, params) do
    grant
    |> cast(params, [:redirect_uri, :expires_in, :scopes])
    |> assoc_constraint(:application)
    |> assoc_constraint(:resource_owner)
    |> put_token()
    |> put_scopes(grant.application.scopes)
    |> validate_scopes(grant.application.scopes)
    |> validate_required([:redirect_uri, :expires_in, :token, :resource_owner, :application])
    |> unique_constraint(:token)
  end

  defp put_token(changeset) do
    put_change(changeset, :token, ExOauth2Provider.Utils.generate_token)
  end
end
