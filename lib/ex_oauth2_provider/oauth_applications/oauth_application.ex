defmodule ExOauth2Provider.OauthApplications.OauthApplication do
  @moduledoc false

  @type t :: %__MODULE__{}

  use ExOauth2Provider.Schema
  require Logger
  alias ExOauth2Provider.Config

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
end
