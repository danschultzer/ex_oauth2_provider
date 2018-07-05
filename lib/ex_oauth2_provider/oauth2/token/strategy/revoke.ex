defmodule ExOauth2Provider.Token.Revoke do
  @moduledoc """
  Functions for dealing with revocation.
  """
  alias ExOauth2Provider.{Token.Utils,
                          Token.Utils.Response,
                          Utils.Error,
                          OauthAccessTokens}

  @doc """
  Revokes access token.

  The authorization server, if applicable, first authenticates the client
  and checks its ownership of the provided token.

  ExOauth2Provider does not use the token_type_hint logic described in the
  RFC 7009 due to the refresh token implementation that is a field in
  the access token schema.

  ## Example confidential client
      ExOauth2Provider.Token.revoke(%{
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "token" => "fi3S9u"
      })
  ## Response
      {:ok, %{}}

  ## Example public client
      ExOauth2Provider.Token.revoke(%{
        "token" => "fi3S9u"
      })
  ## Response
      {:ok, %{}}
  """
  @spec revoke(map()) :: {:ok, map()} | {:error, map(), atom()}
  def revoke(request) do
    %{request: request}
    |> load_client_if_presented()
    |> return_error()
    |> load_access_token()
    |> validate_request()
    |> revoke_token()
    |> Response.revocation_response()
  end

  defp load_client_if_presented(%{request: %{"client_id" => _}} = params),
    do: Utils.load_client(params)
  defp load_client_if_presented(params), do: params

  defp load_access_token(%{error: _} = params), do: params
  defp load_access_token(%{request: %{"token" => _}} = params) do
    params
    |> get_access_token()
    |> get_refresh_token()
    |> preload_token_associations()
  end
  defp load_access_token(params), do: Error.add_error(params, Error.invalid_request())

  defp get_access_token(%{error: _} = params), do: params
  defp get_access_token(%{request: %{"token" => token}} = params) do
    token
    |> OauthAccessTokens.get_by_token
    |> case do
      nil          -> Error.add_error(params, Error.invalid_request())
      access_token -> Map.put(params, :access_token, access_token)
    end
  end

  defp get_refresh_token(%{access_token: _} = params), do: params
  defp get_refresh_token(%{error: _} = params), do: params
  defp get_refresh_token(%{request: %{"token" => token}} = params) do
    token
    |> OauthAccessTokens.get_by_refresh_token
    |> case do
      nil          -> Error.add_error(params, Error.invalid_request())
      access_token -> Map.put(params, :access_token, access_token)
    end
  end

  defp preload_token_associations(%{error: _} = params), do: params
  defp preload_token_associations(%{access_token: access_token} = params) do
    Map.put(params, :acess_token, ExOauth2Provider.repo.preload(access_token, :application))
  end

  defp validate_request(params) do
    params
    |> validate_permissions()
    |> validate_accessible()
  end

  # This will verify permissions on the access token and client.
  #
  # OAuth 2.0 Section 2.1 defines two client types, "public" & "confidential".
  # Public clients (as per RFC 7009) do not require authentication whereas
  # confidential clients must be authenticated for their token revocation.
  #
  # Once a confidential client is authenticated, it must be authorized to
  # revoke the provided access or refresh token. This ensures one client
  # cannot revoke another's tokens.
  #
  # ExOauth2Provider determines the client type implicitly via the presence of the
  # OAuth client associated with a given access or refresh token. Since public
  # clients authenticate the resource owner via "password" or "implicit" grant
  # types, they set the application_id as null (since the claim cannot be
  # verified).
  #
  # https://tools.ietf.org/html/rfc6749#section-2.1
  # https://tools.ietf.org/html/rfc7009
  defp validate_permissions(%{error: _} = params), do: params
  # Client is public, authentication unnecessary
  defp validate_permissions(%{access_token: %{application_id: nil}} = params), do: params
  # Client is confidential, therefore client authentication & authorization is required
  defp validate_permissions(%{access_token: %{application_id: _id}} = params), do: validate_ownership(params)

  defp validate_ownership(%{access_token: %{application_id: application_id}, client: %{id: client_id}} = params) when application_id == client_id, do: params
  defp validate_ownership(params), do: Error.add_error(params, Error.invalid_request())

  defp validate_accessible(%{error: _} = params), do: params
  defp validate_accessible(%{access_token: access_token} = params) do
    case OauthAccessTokens.is_accessible?(access_token) do
      true  -> params
      false -> Error.add_error(params, Error.invalid_request())
    end
  end

  defp revoke_token(%{error: _} = params), do: params
  defp revoke_token(%{access_token: access_token} = params) do
    case OauthAccessTokens.revoke(access_token) do
      {:ok, _}    -> params
      {:error, _} -> Error.add_error(params, Error.invalid_request())
    end
  end

  defp return_error(%{error: _} = params), do: Map.put(params, :should_return_error, true)
  defp return_error(params), do: params
end
