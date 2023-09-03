defmodule Dummy.OauthAccessTokens.OauthAccessToken do
  @moduledoc false

  use Ecto.Schema
  use ExOauth2Provider.AccessTokens.AccessToken, otp_app: :ex_oauth2_provider

  if System.get_env("UUID") do
    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
  end

  schema "oauth_access_tokens" do
    access_token_fields()
    timestamps()
  end

  @impl ExOauth2Provider.Changeset
  def allowed_fields do
    access_token_allowed_fields()
  end

  @impl ExOauth2Provider.Changeset
  def required_fields do
    access_token_required_fields()
  end

  @impl ExOauth2Provider.Changeset
  def request_fields do
    access_token_request_fields()
  end
end
