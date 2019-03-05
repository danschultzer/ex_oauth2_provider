defmodule ExOauth2Provider.OauthAccessGrants.OauthAccessGrant do
  @moduledoc false

  @type t :: %__MODULE__{}

  use ExOauth2Provider.Schema

  alias Ecto.Changeset
  alias ExOauth2Provider.{Config, OauthApplications.OauthApplication, Utils}
  alias ExOauth2Provider.Mixin.Scopes

  schema "oauth_access_grants" do
    belongs_to :resource_owner, Config.resource_owner_struct(:module), Config.resource_owner_struct(:options)
    belongs_to :application, OauthApplication

    field :token,        :string,     null: false
    field :expires_in,   :integer,    null: false
    field :redirect_uri, :string,     null: false
    field :revoked_at,   :naive_datetime, usec: true
    field :scopes,       :string

    timestamps(updated_at: false)
  end

  @spec changeset(t(), map()) :: Changeset.t()
  def changeset(grant, params) do
    grant
    |> Changeset.cast(params, [:redirect_uri, :expires_in, :scopes])
    |> Changeset.assoc_constraint(:application)
    |> Changeset.assoc_constraint(:resource_owner)
    |> put_token()
    |> Scopes.put_scopes(grant.application.scopes)
    |> Scopes.validate_scopes(grant.application.scopes)
    |> Changeset.validate_required([:redirect_uri, :expires_in, :token, :resource_owner, :application])
    |> Changeset.unique_constraint(:token)
  end

  @spec put_token(Ecto.Changeset.t()) :: Ecto.Changeset.t()
  def put_token(changeset) do
    Changeset.put_change(changeset, :token, Utils.generate_token())
  end
end
