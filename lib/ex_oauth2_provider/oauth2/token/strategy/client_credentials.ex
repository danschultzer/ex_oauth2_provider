defmodule ExOauth2Provider.Token.ClientCredentials do
  @moduledoc """
  Functions for dealing with client credentials strategy.
  """
  alias ExOauth2Provider.{
    AccessTokens,
    Token.Utils,
    Token.Utils.Response,
    Utils.Error
  }

  @doc """
  Will grant access token by client credentials.

  ## Example
      ExOauth2Provider.Token.grant(%{
        "grant_type" => "client_credentials",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret"
      }, otp_app: :my_app)

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map(), keyword()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "client_credentials"} = request, config \\ []) do
    {:ok, %{request: request}}
    |> Utils.load_client(config)
    |> issue_access_token_by_creds(config)
    |> Response.response(config)
  end

  defp issue_access_token_by_creds({:error, params}, _config), do: {:error, params}

  defp issue_access_token_by_creds(
         {:ok, %{client: application, request: request} = params},
         config
       ) do
    scopes = request["scope"]

    token_params = %{
      # client_credentials MUST NOT use refresh tokens
      use_refresh_token: false,
      scopes: scopes
    }

    application
    |> AccessTokens.get_application_token_for(scopes, config)
    |> case do
      nil -> AccessTokens.create_application_token(application, token_params, config)
      access_token -> {:ok, access_token}
    end
    |> case do
      {:ok, access_token} -> {:ok, Map.merge(params, %{access_token: access_token})}
      {:error, error} -> Error.add_error({:ok, params}, error)
    end
  end
end
