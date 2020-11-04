defmodule ExOauth2Provider.Token.AuthorizationCode do
  @moduledoc """
  Functions for dealing with authorization code strategy.
  """
  alias ExOauth2Provider.{
    AccessGrants,
    AccessTokens,
    Config,
    Token.Utils,
    Token.Utils.Response,
    Utils.Error}

  @doc """
  Will grant access token by client credentials.

  ## Example
      ExOauth2Provider.Token.grant(%{
        "code" => "1jf6a",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "redirect_uri" => "https://example.com/",
        "grant_type" => "authorization_code"
      }, otp_app: :my_app)

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map(), keyword()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "authorization_code"} = request, config \\ []) do
    {:ok, %{request: request}}
    |> Utils.load_client(config)
    |> load_active_access_grant(config)
    |> validate_redirect_uri()
    |> issue_access_token_by_grant(config)
    |> Response.response(config)
  end

  defp issue_access_token_by_grant({:error, params}, _config), do: {:error, params}

  defp issue_access_token_by_grant(
         {:ok, %{access_grant: access_grant, request: request} = params},
         config
       ) do
    token_params =
      request
      |> Map.take(Config.access_token(config).request_fields())
      |> Map.new(fn {k, v} -> {String.to_atom(k), v} end)
      |> Map.put(:use_refresh_token, Config.use_refresh_token?(config))

    result =
      Config.repo(config).transaction(fn ->
        access_grant
        |> revoke_grant(config)
        |> maybe_create_access_token(token_params, config)
      end)

    case result do
      {:ok, {:error, error}}     -> Error.add_error({:ok, params}, error)
      {:ok, {:ok, access_token}} -> {:ok, Map.put(params, :access_token, access_token)}
      {:error, error}            -> Error.add_error({:ok, params}, error)
    end
  end

  defp revoke_grant(%{revoked_at: nil} = access_grant, config),
    do: AccessGrants.revoke(access_grant, config)

  defp maybe_create_access_token({:error, _} = error, _token_params, _config), do: error

  defp maybe_create_access_token(
         {:ok,
          %{resource_owner: resource_owner, application: application, scopes: scopes} = grant},
         token_params,
         config
       ) do
    token_params =
      grant
      |> Map.drop([:expires_in, :scopes])
      |> Map.take(Config.access_token(config).allowed_fields())
      |> Map.merge(token_params)
      |> Map.merge(%{scopes: scopes, application: application})

    resource_owner
    |> AccessTokens.get_token_for(application, scopes, config)
    |> case do
      nil          -> AccessTokens.create_token(resource_owner, token_params, config)
      access_token -> {:ok, access_token}
    end
  end

  defp load_active_access_grant({:ok, %{client: client, request: %{"code" => code}} = params}, config) do
    client
    |> AccessGrants.get_active_grant_for(code, config)
    |> Config.repo(config).preload(:resource_owner)
    |> Config.repo(config).preload(:application)
    |> case do
      nil          -> Error.add_error({:ok, params}, Error.invalid_grant())
      access_grant -> {:ok, Map.put(params, :access_grant, access_grant)}
    end
  end
  defp load_active_access_grant({:ok, params}, _config), do: Error.add_error({:ok, params}, Error.invalid_grant())
  defp load_active_access_grant({:error, error}, _config), do: {:error, error}

  defp validate_redirect_uri({:error, params}), do: {:error, params}
  defp validate_redirect_uri({:ok, %{request: %{"redirect_uri" => redirect_uri}, access_grant: grant} = params}) do
    case grant.redirect_uri == redirect_uri do
      true  -> {:ok, params}
      false -> Error.add_error({:ok, params}, Error.invalid_grant())
    end
  end
  defp validate_redirect_uri({:ok, params}), do: Error.add_error({:ok, params}, Error.invalid_grant())
end
