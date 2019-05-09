defmodule ExOauth2Provider.Token do
  @moduledoc """
  Handler for dealing with generating access tokens.
  """
  alias ExOauth2Provider.{
    Config,
    Token.Revoke,
    Utils.Error}
  alias Ecto.Schema

  @doc """
  Grants an access token based on grant_type strategy.

  ## Example

      ExOauth2Provider.Token.authorize(resource_owner, %{
        "grant_type" => "invalid",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret"
      }, otp_app: :my_app)

  ## Response

      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map(), keyword()) :: {:ok, Schema.t()} | {:error, map(), term}
  def grant(request, config \\ []) do
    case validate_grant_type(request, config) do
      {:error, :invalid_grant_type} -> Error.unsupported_grant_type()
      {:error, :missing_grant_type} -> Error.invalid_request()
      {:ok, token_module}           -> token_module.grant(request, config)
    end
  end

  defp validate_grant_type(%{"grant_type" => type}, config) do
    type
    |> fetch_module(config)
    |> case do
      nil -> {:error, :invalid_grant_type}
      mod -> {:ok, mod}
    end
  end
  defp validate_grant_type(_, _config), do: {:error, :missing_grant_type}

  defp fetch_module(type, config) do
    config
    |> Config.grant_flows()
    |> grant_type_can_be_used?(type, config)
    |> case do
      true  -> grant_type_to_mod(type)
      false -> nil
    end
  end

  defp grant_type_can_be_used?(_, "refresh_token", config),
    do: Config.use_refresh_token?(config)
  defp grant_type_can_be_used?(_, "password", config),
    do: not is_nil(Config.password_auth(config))
  defp grant_type_can_be_used?(grant_flows, grant_type, _config) do
    Enum.member?(grant_flows, grant_type)
  end

  defp grant_type_to_mod("authorization_code"), do: ExOauth2Provider.Token.AuthorizationCode
  defp grant_type_to_mod("client_credentials"), do: ExOauth2Provider.Token.ClientCredentials
  defp grant_type_to_mod("password"), do: ExOauth2Provider.Token.Password
  defp grant_type_to_mod("refresh_token"), do: ExOauth2Provider.Token.RefreshToken
  defp grant_type_to_mod(_), do: nil

  @doc """
  Revokes an access token as per http://tools.ietf.org/html/rfc7009

  ## Example
      ExOauth2Provider.Token.revoke(resource_owner, %{
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "token" => "fi3S9u"
      }, otp_app: :my_app)

  ## Response

      {:ok, %{}}
  """
  @spec revoke(map(), keyword()) :: {:ok, Schema.t()} | {:error, map(), term()}
  def revoke(request, config \\ []), do: Revoke.revoke(request, config)
end
