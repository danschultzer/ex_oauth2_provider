defmodule ExOauth2Provider.AccessGrants do
  @moduledoc """
  Defines a behaviour for interacting with access grants
  """

  alias Ecto.Schema
  alias ExOauth2Provider.Config

  @callback revoke!(%{optional(atom) => any}, keyword) :: %{optional(atom) => any}
  def revoke!(data, config \\ []), do: strategy(config).revoke!(data, config)

  @callback revoke(%{optional(atom) => any}, keyword) ::
              {:error, Ecto.Changeset.t()} | {:ok, %{optional(atom) => any}}
  def revoke(data, config \\ []), do: strategy(config).revoke(data, config)

  @callback get_active_grant_for(Application.t(), binary(), keyword()) :: AccessGrant.t() | nil
  def get_active_grant_for(application, token, config \\ []),
    do: strategy(config).get_active_grant_for(application, token, config)

  @callback create_grant(Ecto.Schema.t(), Application.t(), map(), keyword()) ::
              {:ok, AccessGrant.t()} | {:error, term()}
  def create_grant(resource_owner, application, attrs, config \\ []),
    do: strategy(config).create_grant(resource_owner, application, attrs, config)

  @callback get_resource_owner_for(Schema.t(), keyword()) :: Schema.t()
  def get_resource_owner_for(access_grant, config \\ []),
    do: strategy(config).get_resource_owner_for(access_grant, config)

  defp strategy(config), do: Config.access_grant_strategy(config)
end
