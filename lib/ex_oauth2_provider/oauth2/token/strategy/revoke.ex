defmodule ExOauth2Provider.Token.Revoke do
  @moduledoc """
  Functions for dealing with revocation.
  """
  alias ExOauth2Provider.{
    AccessTokens,
    Config,
    Token.Utils,
    Token.Utils.Response,
    Utils.Error
  }

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
      }, otp_app: :my_app)

  ## Response
      {:ok, %{}}

  ## Example public client
      ExOauth2Provider.Token.revoke(%{
        "token" => "fi3S9u"
      }, otp_app: :my_app)

  ## Response
      {:ok, %{}}
  """
  @spec revoke(map(), keyword()) :: {:ok, map()} | {:error, map(), atom()}
  def revoke(request, config \\ []) do
    {:ok, %{request: request}}
    |> load_client_if_presented(config)
    |> return_error()
    |> load_access_token(config)
    |> validate_request()
    |> revoke_token(config)
    |> Response.revocation_response(config)
  end

  defp load_client_if_presented({:ok, %{request: %{"client_id" => _}} = params}, config),
    do: Utils.load_client({:ok, params}, config)

  defp load_client_if_presented({:ok, params}, _config), do: {:ok, params}

  defp load_access_token({:error, %{error: _} = params}, _config), do: {:error, params}

  defp load_access_token({:ok, %{request: %{"token" => _}} = params}, config) do
    {:ok, params}
    |> get_access_token(config)
    |> get_refresh_token(config)
    |> preload_token_associations(config)
  end

  defp load_access_token({:ok, params}, _config),
    do: Error.add_error({:ok, params}, Error.invalid_request())

  defp get_access_token({:ok, %{request: %{"token" => token}} = params}, config) do
    token
    |> AccessTokens.get_by_token(config)
    |> case do
      nil -> Error.add_error({:ok, params}, Error.invalid_request())
      access_token -> {:ok, Map.put(params, :access_token, access_token)}
    end
  end

  defp get_refresh_token({:ok, %{access_token: _} = params}, _config), do: {:ok, params}
  defp get_refresh_token({:error, %{error: _} = params}, _config), do: {:error, params}

  defp get_refresh_token({:ok, %{request: %{"token" => token}} = params}, config) do
    token
    |> AccessTokens.get_by_refresh_token(config)
    |> case do
      nil -> Error.add_error({:ok, params}, Error.invalid_request())
      access_token -> {:ok, Map.put(params, :access_token, access_token)}
    end
  end

  defp preload_token_associations({:error, params}, _config), do: {:error, params}

  defp preload_token_associations({:ok, %{access_token: access_token} = params}, config) do
    if is_nil(access_token.application_id) do
      {:ok, params}
    else
      access_token =
        case params do
          %{client: application} ->
            Map.put(access_token, :application, application)

          _ ->
            Config.repo(config).preload(access_token, :application)
        end

      {:ok, Map.put(params, :access_token, access_token)}
    end
  end

  defp validate_request({:error, params}), do: {:error, params}

  defp validate_request({:ok, params}) do
    {:ok, params}
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

  # Client is public, authentication unnecessary
  defp validate_permissions({:ok, %{access_token: %{application_id: nil}} = params}),
    do: {:ok, params}

  # Client is confidential, therefore client authentication & authorization is required
  defp validate_permissions({:ok, %{access_token: %{application_id: _id}} = params}),
    do: validate_ownership({:ok, params})

  defp validate_ownership(
         {:ok,
          %{access_token: %{application_id: application_id}, client: %{id: client_id}} = params}
       )
       when application_id == client_id,
       do: {:ok, params}

  defp validate_ownership({:ok, params}),
    do: Error.add_error({:ok, params}, Error.invalid_request())

  defp validate_accessible({:error, params}), do: {:error, params}

  defp validate_accessible({:ok, %{access_token: access_token} = params}) do
    case AccessTokens.is_accessible?(access_token) do
      true -> {:ok, params}
      false -> Error.add_error({:ok, params}, Error.invalid_request())
    end
  end

  defp revoke_token({:error, params}, _config), do: {:error, params}

  defp revoke_token({:ok, %{access_token: access_token} = params}, config) do
    case AccessTokens.revoke(access_token, config) do
      {:ok, _} -> {:ok, params}
      {:error, _} -> Error.add_error({:ok, params}, Error.invalid_request())
    end
  end

  defp return_error({:error, params}), do: {:error, Map.put(params, :should_return_error, true)}
  defp return_error({:ok, params}), do: {:ok, params}
end
