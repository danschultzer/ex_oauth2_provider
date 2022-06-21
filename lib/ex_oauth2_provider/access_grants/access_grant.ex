defmodule ExOauth2Provider.AccessGrants.AccessGrant do
  @moduledoc """
  Handles the Ecto schema for access grant.

  ## Usage

  Configure `lib/my_project/oauth_access_grants/oauth_access_grant.ex` the following way:

      defmodule MyApp.OauthAccessGrants.OauthAccessGrant do
        use Ecto.Schema
        use ExOauth2Provider.AccessGrants.AccessGrant

        schema "oauth_access_grants" do
          access_grant_fields()

          timestamps()
        end
      end
  """

  @type t :: Ecto.Schema.t()

  @doc false
  def attrs() do
    [
      {:token, :string},
      {:expires_in, :integer},
      {:redirect_uri, :string},
      {:revoked_at, :utc_datetime},
      {:scopes, :string}
    ]
  end

  @doc false
  def assocs() do
    [
      {:belongs_to, :resource_owner, :users},
      {:belongs_to, :application, :applications}
    ]
  end

  @doc false
  def indexes() do
    [
      {:token, true},
    ]
  end

  defmacro __using__(config) do
    quote do
      use ExOauth2Provider.Schema, unquote(config)

      import unquote(__MODULE__), only: [access_grant_fields: 0]
    end
  end

  defmacro access_grant_fields do
    quote do
      ExOauth2Provider.Schema.fields(unquote(__MODULE__))
    end
  end

  alias Ecto.Changeset
  alias ExOauth2Provider.{Mixin.Scopes, Utils}

  @spec changeset(Ecto.Schema.t(), map(), keyword()) :: Changeset.t()
  def changeset(grant, params, config) do
    grant
    |> Changeset.cast(params, [:redirect_uri, :expires_in, :scopes])
    |> Changeset.assoc_constraint(:application)
    |> Changeset.assoc_constraint(:resource_owner)
    |> put_token()
    |> Scopes.put_scopes(grant.application.scopes, config)
    |> Scopes.validate_scopes(grant.application.scopes, config)
    |> Changeset.validate_required([:redirect_uri, :expires_in, :token, :resource_owner, :application])
    |> Changeset.unique_constraint(:token)
  end

  @spec put_token(Ecto.Changeset.t()) :: Ecto.Changeset.t()
  def put_token(changeset) do
    Changeset.put_change(changeset, :token, Utils.generate_token())
  end
end
