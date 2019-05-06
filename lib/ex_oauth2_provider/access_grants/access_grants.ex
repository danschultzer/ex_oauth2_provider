defmodule ExOauth2Provider.AccessGrants do
  @moduledoc """
  The boundary for the OauthAccessGrants system.
  """

  alias ExOauth2Provider.Mixin.{Expirable, Revocable}
  alias ExOauth2Provider.{Applications.Application, AccessGrants.AccessGrant, Utils}

  defdelegate revoke!(data), to: Revocable
  defdelegate revoke(data), to: Revocable

  @doc """
  Gets a single access grant registered with an application.

  ## Examples

      iex> get_active_grant_for(application, "jE9dk")
      %OauthAccessGrant{}

      iex> get_active_grant_for(application, "jE9dk")
      ** nil

  """
  @spec get_active_grant_for(Application.t(), binary()) :: AccessGrant.t() | nil
  def get_active_grant_for(application, token) do
    clauses =
      access_grant()
      |> Utils.belongs_to_clause(:application, application)
      |> Keyword.put(:token, token)

    access_grant()
    |> ExOauth2Provider.repo.get_by(clauses)
    |> Expirable.filter_expired()
    |> Revocable.filter_revoked()
  end

  @doc """
  Creates an access grant.

  ## Examples

      iex> create_grant(resource_owner, application, attrs)
      {:ok, %OauthAccessGrant{}}

      iex> create_grant(resource_owner, application, attrs)
      {:error, %Ecto.Changeset{}}

  """
  @spec create_grant(Ecto.Schema.t(), Application.t(), map()) :: {:ok, AccessGrant.t()} | {:error, term()}
  def create_grant(resource_owner, application, attrs) do
    access_grant()
    |> struct(resource_owner: resource_owner, application: application)
    |> AccessGrant.changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end

  defp access_grant(), do: ExOauth2Provider.Config.access_grant()
end
