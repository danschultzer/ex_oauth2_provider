defmodule ExOauth2Provider.Token.ClientCredentials do
  @moduledoc """
  Functions for dealing with client credentials strategy.
  """
  alias ExOauth2Provider.Token.Util
  alias ExOauth2Provider.Token.Util.Response

  @doc """
  Will grant access token by client credentials.

  ## Example
    resource_owner
    |> ExOauth2Provider.Token.grant(%{
      "grant_type" => "client_credentials",
      "client_id" => "Jf5rM8hQBc",
      "client_secret" => "secret"
    })
  ## Response
    {:ok, access_token}
    {:error, %{error: error, error_description: _}, http_status}

  """
  def grant(%{"grant_type" => "client_credentials"} = request) do
    %{request: request}
    |> Util.load_client
    |> issue_access_token_by_creds
    |> Response.authorize_response
  end

  @doc false
  defp issue_access_token_by_creds(%{error: _} = params), do: params
  defp issue_access_token_by_creds(%{client: client} = params) do
    client = client
    |> ExOauth2Provider.repo.preload(:resource_owner)

    token_params = %{scopes: client.scopes,
                     application: client,
                     # client_credentials MUST NOT use refresh tokens
                     use_refresh_token: false}

    case Util.create_access_token(client.resource_owner, token_params) do
      {:ok, access_token} -> Map.merge(params, %{access_token: access_token})
      {:error, error}     -> Util.add_error(params, error)
    end
  end
end
