defmodule ExOauth2Provider.OauthApplication do
  @moduledoc """
  Ecto schema for oauth access applications
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "oauth_applications" do
    belongs_to :resource_owner, ExOauth2Provider.resource_owner_model

    field :name, :string
    field :uid, :string
    field :secret, :string
    field :redirect_uri, :string
    field :scopes, :string

    has_many :access_tokens, ExOauth2Provider.OauthAccessToken

    timestamps()
  end

  @doc """
  Builds a changeset based on the `struct` and `params`.
  """
  def changeset(struct, params \\ %{}) do
    struct
    |> cast(params, [:name, :secret, :redirect_uri, :scopes])
    |> validate_required([:name, :uid, :secret])
    |> unique_constraint(:uid)
    |> validate_redirect_uri
  end

  def create_changeset(struct, params \\ %{}) do
    struct
    |> cast(params, [:resource_owner_id, :uid, :secret])
    |> cast_assoc(:resource_owner, [:required])
    |> put_uid_if_empty
    |> put_secret_if_empty
    |> changeset(params)
  end

  defp validate_redirect_uri(changeset) do
    uri = changeset
    |> get_stripped_value_from_field(:redirect_uri)
    |> ExOauth2Provider.RedirectURI.validate
    |> case do
      {:error, error} -> add_error(changeset, :redirect_uri, error)
      {:ok, _} -> changeset
    end
  end

  defp put_uid_if_empty(changeset) do
    changeset
    |> put_change_if_empty(:uid, ExOauth2Provider.generate_token)
  end

  defp put_secret_if_empty(changeset) do
    changeset
    |> put_change_if_empty(:secret, ExOauth2Provider.generate_token)
  end

  defp put_change_if_empty(changeset, field, value) do
    case get_stripped_value_from_field(changeset, :secret) do
      "" -> put_change(changeset, field, value)
      _  -> changeset
    end
  end

  defp get_stripped_value_from_field(changeset, field) do
    changeset
    |> get_field(field)
    |> nil_to_string
    |> String.strip
  end

  defp nil_to_string(value) do
    value || ""
  end
end
