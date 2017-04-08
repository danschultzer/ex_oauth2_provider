defmodule ExOauth2Provider.Token do
  @moduledoc """
  Handler for dealing with generating access tokens.
  """
  alias ExOauth2Provider.Token.AuthorizationCode
  alias ExOauth2Provider.Token.ClientCredentials
  alias ExOauth2Provider.Token.Password
  alias ExOauth2Provider.Token.RefreshToken
  alias ExOauth2Provider.Token.Revoke
  alias ExOauth2Provider.Utils.Error

  @doc """
  Grants an access token based on grant_type strategy.

  ## Example
    resource_owner
    |> ExOauth2Provider.Token.authorize(%{
      "grant_type" => "invalid",
      "client_id" => "Jf5rM8hQBc",
      "client_secret" => "secret"
    })
  ## Response
    {:error, %{error: error, error_description: _}, http_status}
  """
  def grant(request) do
    case request do
      %{"grant_type" => "authorization_code"} -> AuthorizationCode.grant(request)
      %{"grant_type" => "client_credentials"} -> ClientCredentials.grant(request)
      %{"grant_type" => "password"}           -> Password.grant(request)
      %{"grant_type" => "refresh_token"}      -> RefreshToken.grant(request)
      %{"grant_type" => _}                    -> Error.unsupported_grant_type()
      _                                       -> Error.invalid_request()
    end
  end

  @doc """
  Revokes an access token.

  http://tools.ietf.org/html/rfc7009

  ## Example
    resource_owner
    |> ExOauth2Provider.Token.revoke(%{
      "client_id" => "Jf5rM8hQBc",
      "client_secret" => "secret",
      "token" => "fi3S9u"
    })
  ## Response
    {:ok, %{}}
  """
  def revoke(request) do
    Revoke.revoke(request)
  end
end
