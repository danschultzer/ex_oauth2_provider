defmodule ExOauth2Provider.Authorization do
  @moduledoc """
  Handler for dealing with generating access grants.
  """
  alias ExOauth2Provider.{Config,
                          Utils.Error,
                          Authorization.Utils,
                          Authorization.Utils.Response}
  alias Ecto.Schema

  @doc """
  Check ExOauth2Provider.Authorization.Code for usage.
  """
  @spec preauthorize(Schema.t(), map()) :: Response.success() | Response.error() | Response.redirect() | Response.native_redirect()
  def preauthorize(resource_owner, request) do
    case validate_response_type(request) do
      {:error, :invalid_response_type} -> unsupported_response_type(resource_owner, request)
      {:error, :missing_response_type} -> invalid_request(resource_owner, request)
      {:ok, token_module}              -> token_module.preauthorize(resource_owner, request)
    end
  end

  @doc """
  Check ExOauth2Provider.Authorization.Code for usage.
  """
  @spec authorize(Schema.t(), map()) :: {:ok, binary()} | Response.error() | Response.redirect() | Response.native_redirect()
  def authorize(resource_owner, request) do
    case validate_response_type(request) do
      {:error, :invalid_response_type} -> unsupported_response_type(resource_owner, request)
      {:error, :missing_response_type} -> invalid_request(resource_owner, request)
      {:ok, token_module}              -> token_module.authorize(resource_owner, request)
    end
  end

  @doc """
  Check ExOauth2Provider.Authorization.Code for usage.
  """
  @spec deny(Schema.t(), map()) :: Response.error() | Response.redirect()
  def deny(resource_owner, request) do
    case validate_response_type(request) do
      {:error, :invalid_response_type} -> unsupported_response_type(resource_owner, request)
      {:error, :missing_response_type} -> invalid_request(resource_owner, request)
      {:ok, token_module}              -> token_module.deny(resource_owner, request)
    end
  end

  defp unsupported_response_type(resource_owner, request),
    do: handle_error_response(resource_owner, request, Error.unsupported_response_type())

  defp invalid_request(resource_owner, request),
    do: handle_error_response(resource_owner, request, Error.invalid_request())

  defp handle_error_response(resource_owner, request, error) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> Error.add_error(error)
    |> Response.error_response()
  end

  defp validate_response_type(%{"response_type" => type}) do
    type
    |> response_type_to_grant_flow()
    |> fetch_module()
    |> case do
      nil -> {:error, :invalid_response_type}
      mod -> {:ok, mod}
    end
  end
  defp validate_response_type(_), do: {:error, :missing_response_type}

  defp response_type_to_grant_flow("code"), do: "authorization_code"
  defp response_type_to_grant_flow(_), do: nil

  defp fetch_module(grant_flow) do
    Config.grant_flows()
    |> flow_can_be_used?(grant_flow)
    |> case do
      true  -> flow_to_mod(grant_flow)
      false -> nil
    end
  end

  defp flow_can_be_used?(grant_flows, grant_flow) do
    Enum.member?(grant_flows, grant_flow)
  end

  defp flow_to_mod("authorization_code"), do: ExOauth2Provider.Authorization.Code
  defp flow_to_mod(_), do: nil
end
