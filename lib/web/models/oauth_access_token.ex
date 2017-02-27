defmodule ExOauth2Provider.OauthAccessToken do
  use Ecto.Schema
  import Ecto.Changeset

  @scopes Enum.join(Application.get_env(:ex_oauth2_provider, :scopes, []), ",")

  schema "oauth_access_tokens" do
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
    |> unique_constraint(:token)
    |> unique_constraint(:refresh_token)
  end

  def create_changeset(struct, params \\ %{}) do
    struct
    |> cast(params, [:resource_owner_id])
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

  defp put_access_token(model_changeset) do
    put_change(model_changeset, :token, ExOauth2Provider.generate_token)
  end

  defp put_refresh_token(model_changeset) do
    put_change(model_changeset, :refresh_token, ExOauth2Provider.generate_token)
  end

  defp put_scopes(model_changeset) do
    put_change(model_changeset, :details, %{scope: @scopes})
  end
end
