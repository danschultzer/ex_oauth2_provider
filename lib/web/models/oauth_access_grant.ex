defmodule ExOauth2Provider.OauthAccessGrant do
  @moduledoc """
  Ecto schema for oauth access token grants
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_access_grants" do
    belongs_to :application, ExOauth2Provider.OauthApplication
    belongs_to :resource_owner, ExOauth2Provider.resource_owner_model

    field :token,       :string
    field :expires_in,  :integer
    field :revoked_at,  :naive_datetime, usec: true
    field :scopes,      :string

    timestamps(updated_at: false)
  end

  @doc """
  Builds a changeset based on the `struct` and `params`.
  """
  def create_changeset(struct, params \\ %{}) do
    struct
    |> cast(params, [:expires_in, :scopes, :resource_owner_id, :application_id])
    |> cast_assoc(:application, [:required])
    |> cast_assoc(:resource_owner, [:required])
    |> put_token
    |> validate_required([:expires_in, :token, :resource_owner_id, :application_id])
    |> assoc_constraint(:resource_owner)
    |> assoc_constraint(:application)
    |> unique_constraint(:token)
    |> unique_constraint(:refresh_token)
  end

  def create_grant(attrs \\ %{}) do
    %ExOauth2Provider.OauthAccessGrant{}
    |> create_changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end

  defp put_token(changeset) do
    changeset
    |> put_change(:token, ExOauth2Provider.generate_token)
  end
end
