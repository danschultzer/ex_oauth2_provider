defmodule ExOauth2Provider.Token do
  @moduledoc """
  Handler for dealing with generating access tokens.
  """
  alias ExOauth2Provider.Token.AuthorizationCode
  alias ExOauth2Provider.Token.ClientCredentials
  alias ExOauth2Provider.Token.Password
  alias ExOauth2Provider.Token.RefreshToken
  alias ExOauth2Provider.Utils.Error

  def grant(%{"grant_type" => "authorization_code"} = request),
    do: AuthorizationCode.grant(request)
  def grant(%{"grant_type" => "client_credentials"} = request),
    do: ClientCredentials.grant(request)
  def grant(%{"grant_type" => "password"} = request),
    do: Password.grant(request)
  def grant(%{"grant_type" => "refresh_token"} = request),
    do: RefreshToken.grant(request)
  def grant(%{"grant_type" => _}), do: Error.unsupported_grant_type()
  def grant(_), do: Error.invalid_request()
end
