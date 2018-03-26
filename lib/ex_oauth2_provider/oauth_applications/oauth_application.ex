defmodule ExOauth2Provider.OauthApplications.OauthApplication do
  @moduledoc false

  use ExOauth2Provider.Schema
  require Logger
  alias ExOauth2Provider.{Config, Utils}

  # For Phoenix integrations
  if Code.ensure_loaded?(Phoenix.Param) do
    @derive {Phoenix.Param, key: :uid}
  end

  @owner_struct Config.application_owner_struct()
  @owner_belongs_to_opts Utils.schema_belongs_to_opts(@owner_struct)
  if is_nil(@owner_struct), do: Logger.error("You need to set a resource_owner or application_owner in your config and recompile ex_oauth2_provider!")

  schema "oauth_applications" do
    belongs_to :owner, @owner_struct, @owner_belongs_to_opts

    field :name,         :string,     null: false
    field :uid,          :string,     null: false
    field :secret,       :string,     null: false
    field :redirect_uri, :string,     null: false
    field :scopes,       :string,     null: false, default: ""

    has_many :access_tokens, ExOauth2Provider.OauthAccessTokens.OauthAccessToken, foreign_key: :application_id

    timestamps()
  end
end
