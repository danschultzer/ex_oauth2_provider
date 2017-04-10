defmodule ExOauth2Provider.Authorization do
  @moduledoc """
  Handler for dealing with generating access grants.
  """
  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Authorization.Utils
  alias ExOauth2Provider.Authorization.Utils.Response

  @doc """
  Check ExOauth2Provider.Authorization.Code for usage.
  """
  def preauthorize(resource_owner, request, config \\ ExOauth2Provider.Config) do
    case validate_response_type(request, config) do
      {:error, :invalid_response_type} -> unsupported_response_type(resource_owner, request)
      {:error, :missing_response_type} -> invalid_request(resource_owner, request)
      {:ok, token_module}              -> apply(token_module, :preauthorize, [resource_owner, request])
    end
  end

  @doc """
  Check ExOauth2Provider.Authorization.Code for usage.
  """
  def authorize(resource_owner, request, config \\ ExOauth2Provider.Config) do
    case validate_response_type(request, config) do
      {:error, :invalid_response_type} -> unsupported_response_type(resource_owner, request)
      {:error, :missing_response_type} -> invalid_request(resource_owner, request)
      {:ok, token_module}              -> apply(token_module, :authorize, [resource_owner, request])
    end
  end

  @doc """
  Check ExOauth2Provider.Authorization.Code for usage.
  """
  def deny(resource_owner, request, config \\ ExOauth2Provider.Config) do
    case validate_response_type(request, config) do
      {:error, :invalid_response_type} -> unsupported_response_type(resource_owner, request)
      {:error, :missing_response_type} -> invalid_request(resource_owner, request)
      {:ok, token_module}              -> apply(token_module, :deny, [resource_owner, request])
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
    |> Response.error_response
  end

  defp validate_response_type(%{"response_type" => response_type}, config) do
    case Keyword.fetch(config.calculate_authorization_response_types(), String.to_atom(response_type)) do
      {:ok, authorization_module} -> {:ok, authorization_module}
      :error                      -> {:error, :invalid_response_type}
    end
  end
  defp validate_response_type(_, _), do: {:error, :missing_response_type}
end
