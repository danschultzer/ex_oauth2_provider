defmodule ExOauth2Provider.Factory do
  @moduledoc """
  Generates factories
  """

  @config Application.get_env(:ex_oauth2_provider, ExOauth2Provider, [])
  @repo Keyword.get(@config, :repo)
  @resource_owner_model Keyword.get(@config, :resource_owner_model)
  @access_token ExOauth2Provider.OauthAccessToken

  use ExMachina.Ecto, repo: @repo

  def access_token_factory do
    %@access_token{
      scopes: "read,write"
    }
  end

  def user_factory do
    %@resource_owner_model{
      email: sequence(:email, &"foo-#{&1}@example.com")
    }
  end
end
