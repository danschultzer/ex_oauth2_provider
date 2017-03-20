defmodule ExOauth2Provider.OauthAccessToken do
  @moduledoc """
  Ecto schema for oauth access tokens
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_access_tokens" do
    belongs_to :application, ExOauth2Provider.OauthApplication, on_replace: :nilify
    belongs_to :resource_owner, ExOauth2Provider.resource_owner_model

    field :token, :string
    field :refresh_token, :string
    field :expires_in, :integer
    field :revoked_at, :naive_datetime, usec: true
    field :scopes, :string

    timestamps()
  end

  @doc """
  Builds a changeset based on the `struct` and `params`.
  """
  def changeset(struct, params \\ %{}) do
    struct
    |> cast(params, [:expires_in, :revoked_at])
    |> validate_required([:token, :resource_owner_id])
    |> assoc_constraint(:resource_owner)
    |> unique_constraint(:token)
    |> unique_constraint(:refresh_token)
  end

  def create_changeset(struct, params \\ %{}) do
    struct
    |> cast(params, [:resource_owner_id, :application_id])
    |> cast_assoc(:application)
    |> cast_assoc(:resource_owner, [:required])
    |> put_access_token
    |> put_refresh_token
    |> put_scopes
    |> changeset(params)
    |> unique_constraint(:token)
    |> unique_constraint(:refresh_token)
  end

  def is_expired?(access_token) do
    case access_token.expires_in do
      nil -> false
      expires_in ->
        expires_at = access_token.inserted_at
          |> NaiveDateTime.add(expires_in, :second)
        NaiveDateTime.compare(expires_at, NaiveDateTime.utc_now) == :lt
    end
  end

  def is_accessible?(access_token) do
    !is_expired?(access_token) and is_nil(access_token.revoked_at)
  end

  defp put_access_token(changeset) do
    changeset
    |> put_change(:token, ExOauth2Provider.generate_token)
  end

  defp put_refresh_token(changeset) do
    changeset
    |> put_change(:refresh_token, ExOauth2Provider.generate_token)
  end

  defp put_scopes(changeset) do
    changeset
    |> put_change(:scopes, default_scopes_string)
  end

  defp default_scopes_string do
    ExOauth2Provider.default_scopes
    |> ExOauth2Provider.Scopes.to_string
  end
end
