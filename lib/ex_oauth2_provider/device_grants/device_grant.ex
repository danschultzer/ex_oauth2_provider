defmodule ExOauth2Provider.DeviceGrants.DeviceGrant do
  @moduledoc """
  Handles the Ecto schema for device grant.

  ## Usage

  Configure `lib/my_project/oauth_device_grants/oauth_device_grant.ex` the following way:

      defmodule MyApp.OauthDeviceGrants.OauthDeviceGrant do
        use Ecto.Schema
        use ExOauth2Provider.DeviceGrants.DeviceGrant

        schema "oauth_device_grants" do
          device_grant_fields()

          timestamps()
        end
      end
  """

  @type t :: Ecto.Schema.t()

  @doc false
  def attrs() do
    [
      {:device_code, :string, null: false},
      {:expires_in, :integer, null: false},
      {:last_polled_at, :utc_datetime},
      {:scopes, :string},
      {:user_code, :string}
    ]
  end

  @doc false
  def assocs() do
    [
      {:belongs_to, :application, :applications},
      {:belongs_to, :resource_owner, :users}
    ]
  end

  @doc false
  def indexes() do
    [
      {:device_code, true},
      {:user_code, true}
    ]
  end

  defmacro __using__(config) do
    quote do
      use ExOauth2Provider.Schema, unquote(config)

      import unquote(__MODULE__), only: [device_grant_fields: 0]
    end
  end

  defmacro device_grant_fields do
    quote do
      ExOauth2Provider.Schema.fields(unquote(__MODULE__))
    end
  end

  alias Ecto.Changeset
  alias ExOauth2Provider.Mixin.Scopes

  @spec changeset(Ecto.Schema.t(), map(), keyword()) :: Changeset.t()
  def changeset(grant, params, config) do
    grant
    |> Changeset.cast(
      params,
      [
        :device_code,
        :expires_in,
        :last_polled_at,
        :resource_owner_id,
        :scopes,
        :user_code
      ]
    )
    |> Changeset.assoc_constraint(:application)
    |> Changeset.assoc_constraint(:resource_owner)
    |> Scopes.put_scopes(grant.application.scopes, config)
    |> Scopes.validate_scopes(grant.application.scopes, config)
    |> Changeset.validate_required([
      :device_code,
      :expires_in,
      :application
    ])
    |> Changeset.unique_constraint(:device_code)
    |> Changeset.unique_constraint(:user_code)
  end
end
