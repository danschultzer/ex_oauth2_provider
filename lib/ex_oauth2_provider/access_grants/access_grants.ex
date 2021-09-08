defmodule ExOauth2Provider.AccessGrants do
  @moduledoc """
  The boundary for the OauthAccessGrants system.
  """

  alias ExOauth2Provider.Mixin.{Expirable, Revocable}
  alias ExOauth2Provider.{Applications.Application, AccessGrants.AccessGrant, Config}

  defdelegate revoke!(data, config \\ []), to: Revocable
  defdelegate revoke(data, config \\ []), to: Revocable

  @doc """
  Gets a single access grant registered with an application.

  ## Examples

      iex> get_active_grant_for(application, "jE9dk", otp_app: :my_app)
      %OauthAccessGrant{}

      iex> get_active_grant_for(application, "jE9dk", otp_app: :my_app)
      ** nil

  """
  @spec get_active_grant_for(Application.t(), binary(), keyword()) :: AccessGrant.t() | nil
  def get_active_grant_for(application, token, config \\ []) do
    get_active_grant_with_criteria(
      [application_id: application.id, token: token],
      config
    )
  end

  @doc """
  Creates an access grant.

  ## Examples

      iex> create_grant(resource_owner, application, attrs)
      {:ok, %OauthAccessGrant{}}

      iex> create_grant(resource_owner, application, attrs)
      {:error, %Ecto.Changeset{}}

  """
  @spec create_grant(Ecto.Schema.t(), Application.t(), map(), keyword()) ::
          {:ok, AccessGrant.t()} | {:error, term()}
  def create_grant(resource_owner, application, attrs, config \\ []) do
    config
    |> Config.access_grant()
    |> struct(resource_owner: resource_owner, application: application)
    |> AccessGrant.changeset(attrs, config)
    |> Config.repo(config).insert()
  end

  @doc """
  Retrieve active grant for the given resource owner and token.
  """
  @spec get_active_grant_for_owner_by_token(Ecto.Schema.t(), binary(), keyword()) ::
          AccessGrant.t() | nil
  def get_active_grant_for_owner_by_token(owner, token, config \\ []) do
    get_active_grant_with_criteria(
      [token: token, resource_owner_id: owner.id],
      config
    )
  end

  defp get_active_grant_with_criteria(criteria, config) do
    config
    |> Config.access_grant()
    |> Config.repo(config).get_by(criteria)
    |> Expirable.filter_expired()
    |> Revocable.filter_revoked()
  end
end
