defmodule ExOauth2Provider.AccessTokens.AccessToken do
  @moduledoc """
  Handles the Ecto schema for access token.

  ## Usage

  Configure `lib/my_project/oauth_access_tokens/oauth_access_token.ex` the following way:

      defmodule MyApp.OauthAccessTokens.OauthAccessToken do
        use Ecto.Schema
        use ExOauth2Provider.AccessTokens.AccessToken

        schema "oauth_access_tokens" do
          access_token_fields()

          timestamps()
        end
      end
  """
  alias ExOauth2Provider.Schema

  @type t :: Ecto.Schema.t()

  @doc false
  def attrs() do
    [
      {:token, :string},
      {:refresh_token, :string},
      {:expires_in, :integer},
      {:revoked_at, :utc_datetime},
      {:scopes, :string},
      {:previous_refresh_token, :string, default: ""}
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
      {:refresh_token, true}
    ]
  end

  defmacro __using__(config) do
    quote do
      use ExOauth2Provider.Schema, unquote(config)

      import unquote(__MODULE__), only: [access_token_fields: 0]
    end
  end

  defmacro access_token_fields do
    quote do
      ExOauth2Provider.Schema.fields(unquote(__MODULE__))
    end
  end

  alias Ecto.Changeset
  alias ExOauth2Provider.{Config, Mixin.Scopes, Utils}

  @spec changeset(Ecto.Schema.t(), map(), keyword()) :: Changeset.t()
  def changeset(token, params, config \\ []) do
    server_scopes = server_scopes(token)

    token
    |> Changeset.cast(params, [:expires_in, :scopes])
    |> validate_application_or_resource_owner()
    |> put_previous_refresh_token(params[:previous_refresh_token])
    |> put_refresh_token(params[:use_refresh_token])
    |> Scopes.put_scopes(server_scopes, config)
    |> Scopes.validate_scopes(server_scopes, config)
    |> put_token(config)
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

  defp put_token(changeset, config) do
    changeset
    |> Changeset.change(%{token: gen_token(changeset, config)})
    |> Changeset.validate_required([:token])
    |> Changeset.unique_constraint(:token)
  end

  defp gen_token(%{data: %struct{}} = changeset, config) do
    created_at = Schema.__timestamp_for__(struct, :inserted_at)

    opts =
      changeset
      |> Changeset.apply_changes()
      |> Map.take([:resource_owner, :scopes, :application, :expires_in])
      |> Map.put(:created_at, created_at)
      |> Enum.into([])

    opts = Keyword.put(opts, :resource_owner_id, resource_owner_id(opts[:resource_owner]))

    case Config.access_token_generator(config) do
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
