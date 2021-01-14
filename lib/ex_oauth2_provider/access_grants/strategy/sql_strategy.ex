defmodule ExOauth2Provider.AccessGrants.Strategy.SqlStrategy do
  @moduledoc """
  Standard Postgres-based access token implementation strategy
  """
  @behaviour ExOauth2Provider.AccessGrants

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
    config
    |> Config.access_grant()
    |> Config.repo(config).get_by(application_id: application.id, token: token)
    |> Expirable.filter_expired()
    |> Revocable.filter_revoked()
    |> Config.repo(config).preload(:resource_owner)
    |> Config.repo(config).preload(:application)
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
  Returns the resource owner associated with an access_grant.

  ## Examples

      iex> get_resource_owner_for(access_grant)
      %User{}

      iex> get_resource_owner_for(access_grant)
      nil

  """
  @spec get_resource_owner_for(AccessGrant.t(), keyword()) :: Ecto.Schema.t()
  def get_resource_owner_for(resource_owner, config \\ [])

  def get_resource_owner_for(%{resource_owner: %{id: _id} = resource_owner}, _config),
    do: resource_owner

  def get_resource_owner_for(access_grant, config) do
    access_grant
    |> Config.repo(config).preload(:resource_owner)
    |> Map.get(:resource_owner)
  end
end
