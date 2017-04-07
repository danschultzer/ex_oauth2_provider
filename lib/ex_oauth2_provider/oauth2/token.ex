defmodule ExOauth2Provider.Token do
  @moduledoc """
  Handler for dealing with generating access tokens.
  """
  alias ExOauth2Provider.Token.AuthorizationCode
  alias ExOauth2Provider.Token.ClientCredentials

  alias ExOauth2Provider.Token.Util.Error
  alias ExOauth2Provider.Token.Util.Response

  def grant(%{"grant_type" => "authorization_code"} = request),
    do: AuthorizationCode.grant(request)
  def grant(%{"grant_type" => "client_credentials"} = request),
    do: ClientCredentials.grant(request)
  def grant(%{"grant_type" => _}), do: Error.unsupported_grant_type()
  def grant(_), do: Error.invalid_request()
end
