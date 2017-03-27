defmodule ExOauth2Provider.OauthApplications.OauthApplication do
  @moduledoc """
  Ecto schema for oauth access applications
  """

  use Ecto.Schema
  #
  # # Use macro and set up schema in phoenix with this macro
  # if Code.ensure_loaded?(Phoenix.Param) do
  #   @derive {Phoenix.Param, key: :uid}
  # end

  schema "oauth_applications" do
    belongs_to :resource_owner, ExOauth2Provider.resource_owner_model

    field :name,         :string,     null: false
    field :uid,          :string,     null: false
    field :secret,       :string,     null: false
    field :redirect_uri, :string,     null: false
    field :scopes,       :string,     null: false, default: ""

    has_many :access_tokens, ExOauth2Provider.OauthAccessTokens.OauthAccessToken

    timestamps()
  end
end
