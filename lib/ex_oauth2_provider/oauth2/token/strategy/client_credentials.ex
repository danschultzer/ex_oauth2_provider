defmodule ExOauth2Provider.Token.ClientCredentials do
  @moduledoc """
  Functions for dealing with client credentials strategy.
  """
  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Token.Utils
  alias ExOauth2Provider.Token.Utils.Response

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
  def grant(%{"grant_type" => "client_credentials"} = request, config \\ ExOauth2Provider.Config) do
    %{request: request}
    |> Utils.load_client
    |> validate_request
    |> issue_access_token_by_creds
    |> Response.response(config)
  end

  defp issue_access_token_by_creds(%{error: _} = params), do: params
  defp issue_access_token_by_creds(%{client: client, request: request} = params) do
    token_params = %{scopes: request["scope"],
                     # client_credentials MUST NOT use refresh tokens
                     use_refresh_token: false}

    case Utils.find_or_create_access_token(client, token_params) do
      {:ok, access_token} -> Map.merge(params, %{access_token: access_token})
      {:error, error}     -> Error.add_error(params, error)
    end
  end

  defp validate_request(params), do: params
end
