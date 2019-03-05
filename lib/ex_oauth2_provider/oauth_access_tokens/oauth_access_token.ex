defmodule ExOauth2Provider.OauthAccessTokens.OauthAccessToken do
  @moduledoc false

  @type t :: %__MODULE__{}

  use ExOauth2Provider.Schema

  alias Ecto.Changeset
  alias ExOauth2Provider.{Config, Mixin.Scopes, OauthApplications.OauthApplication, Utils}

  schema "oauth_access_tokens" do
    belongs_to :resource_owner, Config.resource_owner_struct(:module), Config.resource_owner_struct(:options)
    belongs_to :application, OauthApplication, on_replace: :nilify

    field :token,         :string, null: false
    field :refresh_token, :string
    field :expires_in,    :integer
    field :revoked_at,    :naive_datetime, usec: true
    field :scopes,        :string
    field :previous_refresh_token, :string, null: false, default: ""

    timestamps()
  end

  @spec changeset(t(), map()) :: Changeset.t()
  def changeset(token, params) do
    server_scopes = server_scopes(token)

    token
    |> Changeset.cast(params, [:expires_in, :scopes])
    |> validate_application_or_resource_owner()
    |> put_previous_refresh_token(params[:previous_refresh_token])
    |> put_refresh_token(params[:use_refresh_token])
    |> Scopes.put_scopes(server_scopes)
    |> Scopes.validate_scopes(server_scopes)
    |> put_token()
  end

  defp server_scopes(%{application: %{scopes: scopes}}), do: scopes
  defp server_scopes(_), do: nil

  defp validate_application_or_resource_owner(changeset) do
    cond do
      is_nil(Changeset.get_field(changeset, :application)) ->
        validate_resource_owner(changeset)

      is_nil(Changeset.get_field(changeset, :resource_owner)) ->
        validate_application(changeset)

      true ->
        changeset
        |> validate_resource_owner()
        |> validate_application()
    end
  end

  defp validate_application(changeset) do
    changeset
    |> Changeset.validate_required([:application])
    |> Changeset.assoc_constraint(:application)
  end

  defp validate_resource_owner(changeset) do
    changeset
    |> Changeset.validate_required([:resource_owner])
    |> Changeset.assoc_constraint(:resource_owner)
  end

  defp put_token(changeset) do
    changeset
    |> Changeset.change(%{token: gen_token(changeset)})
    |> Changeset.validate_required([:token])
    |> Changeset.unique_constraint(:token)
  end

  defp gen_token(changeset) do
    opts =
      changeset
      |> Changeset.apply_changes()
      |> Map.take([:resource_owner, :scopes, :application, :expires_in])
      |> Map.put(:created_at, %{NaiveDateTime.utc_now() | microsecond: {0, 0}})
      |> Enum.into([])

    opts = Keyword.put(opts, :resource_owner_id, resource_owner_id(opts[:resource_owner]))

    case Config.access_token_generator() do
      nil              -> Utils.generate_token(opts)
      {module, method} -> apply(module, method, [opts])
    end
  end

  defp resource_owner_id(%{id: id}), do: id
  defp resource_owner_id(_), do: nil

  defp put_previous_refresh_token(changeset, nil), do: changeset
  defp put_previous_refresh_token(changeset, refresh_token),
    do: Changeset.change(changeset, %{previous_refresh_token: refresh_token.refresh_token})

  defp put_refresh_token(changeset, true) do
    changeset
    |> Changeset.change(%{refresh_token: Utils.generate_token()})
    |> Changeset.validate_required([:refresh_token])
  end
  defp put_refresh_token(changeset, _), do: changeset
end
