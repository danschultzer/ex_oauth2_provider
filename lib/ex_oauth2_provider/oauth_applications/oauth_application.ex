defmodule ExOauth2Provider.OauthApplications.OauthApplication do
  @moduledoc false

  @type t :: %__MODULE__{}

  use ExOauth2Provider.Schema
  require Logger

  alias Ecto.Changeset
  alias ExOauth2Provider.{Config, RedirectURI, Utils}
  import ExOauth2Provider.Mixin.Scopes

  # For Phoenix integrations
  if Code.ensure_loaded?(Phoenix.Param) do
    @derive {Phoenix.Param, key: :uid}
  end

  if is_nil(Config.application_owner_struct(:module)), do: Logger.error("You need to set a resource_owner or application_owner in your config and recompile ex_oauth2_provider!")

  schema "oauth_applications" do
    belongs_to :owner, Config.application_owner_struct(:module), Config.application_owner_struct(:options)

    field :name,         :string,     null: false
    field :uid,          :string,     null: false
    field :secret,       :string,     null: false, default: ""
    field :redirect_uri, :string,     null: false
    field :scopes,       :string,     null: false, default: ""

    has_many :access_tokens, ExOauth2Provider.OauthAccessTokens.OauthAccessToken, foreign_key: :application_id

    timestamps()
  end

  @spec changeset(t(), map()) :: Changeset.t()
  def changeset(application, params) do
    application
    |> maybe_new_application_changeset(params)
    |> Changeset.cast(params, [:name, :secret, :redirect_uri, :scopes])
    |> Changeset.validate_required([:name, :uid, :redirect_uri])
    |> validate_secret_not_nil()
    |> validate_scopes()
    |> validate_redirect_uri()
    |> Changeset.unique_constraint(:uid)
  end

  defp validate_secret_not_nil(changeset) do
    case Changeset.get_field(changeset, :secret) do
      nil -> Changeset.add_error(changeset, :secret, "can't be blank")
      _   -> changeset
    end
  end

  defp maybe_new_application_changeset(application, params) do
    case Ecto.get_meta(application, :state) do
      :built  -> new_application_changeset(application, params)
      :loaded -> application
    end
  end

  defp new_application_changeset(application, params) do
    application
    |> Changeset.cast(params, [:uid, :secret])
    |> put_uid()
    |> put_secret()
    |> put_scopes()
    |> Changeset.assoc_constraint(:owner)
  end

  defp validate_redirect_uri(changeset) do
    url = Changeset.get_field(changeset, :redirect_uri) || ""

    url
    |> String.split()
    |> Enum.reduce(changeset, &validate_redirect_uri(&2, &1))
  end

  defp validate_redirect_uri(changeset, url) do
    url
    |> RedirectURI.validate
    |> case do
       {:error, error} -> Changeset.add_error(changeset, :redirect_uri, error)
       {:ok, _}        -> changeset
     end
  end

  defp put_uid(%{changes: %{uid: _}} = changeset), do: changeset
  defp put_uid(%{} = changeset) do
    Changeset.change(changeset, %{uid: Utils.generate_token()})
  end

  defp put_secret(%{changes: %{secret: _}} = changeset), do: changeset
  defp put_secret(%{} = changeset) do
    Changeset.change(changeset, %{secret: Utils.generate_token()})
  end
end
