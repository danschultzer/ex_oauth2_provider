defmodule ExOauth2Provider.Token.ClientCredentials do
  @moduledoc """
  Functions for dealing with client credentials strategy.
  """
  alias ExOauth2Provider.{AccessTokens,
                          Token.Utils,
                          Token.Utils.Response,
                          Utils.Error}

  @doc """
  Will grant access token by client credentials.

  ## Example
      ExOauth2Provider.Token.grant(%{
        "grant_type" => "client_credentials",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret"
      })

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "client_credentials"} = request) do
    {:ok, %{request: request}}
    |> Utils.load_client()
    |> issue_access_token_by_creds()
    |> Response.response()
  end

  defp issue_access_token_by_creds({:error, params}), do: {:error, params}
  defp issue_access_token_by_creds({:ok, %{client: application, request: request} = params}) do
    scopes = request["scope"]
    token_params = %{
      use_refresh_token: false, # client_credentials MUST NOT use refresh tokens
      scopes: scopes
    }

    application
    |> AccessTokens.get_application_token_for(scopes)
    |> case do
      nil          -> AccessTokens.create_application_token(application, token_params)
      access_token -> {:ok, access_token}
    end
    |> case do
      {:ok, access_token} -> {:ok, Map.merge(params, %{access_token: access_token})}
      {:error, error}     -> Error.add_error({:ok, params}, error)
    end
  end
end
