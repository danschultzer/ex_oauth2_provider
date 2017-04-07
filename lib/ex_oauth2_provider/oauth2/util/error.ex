defmodule ExOauth2Provider.Util.Error do
  @doc false
  def invalid_request do
    msg = "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    {:error, %{error: :invalid_request, error_description: msg}, :bad_request}
  end

  @doc false
  def invalid_client do
    msg = "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
    {:error, %{error: :invalid_client, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  def invalid_grant do
    msg = "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
    {:error, %{error: :invalid_grant, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  def unsupported_grant_type do
    msg = "The authorization grant type is not supported by the authorization server."
    {:error, %{error: :unsupported_grant_type, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  def invalid_scopes do
    msg = "The requested scope is invalid, unknown, or malformed."
    {:error, %{error: :invalid_scope, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  def invalid_redirect_uri do
    msg = "The redirect uri included is not valid."
    {:error, %{error: :invalid_redirect_uri, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  def access_denied do
    msg = "The resource owner or authorization server denied the request."
    {:error, %{error: :access_denied, error_description: msg}, :unauthorized}
  end

  @doc false
  def unsupported_response_type do
    msg = "The authorization server does not support this response type."
    {:error, %{error: :unsupported_response_type, error_description: msg}, :unprocessable_entity}
  end
end
