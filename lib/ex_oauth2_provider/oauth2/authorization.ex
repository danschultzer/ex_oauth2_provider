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
  @spec preauthorize(Ecto.Schema.t, Map.t) :: {:ok, Ecto.Schema.t, [String.t]} |
                                              {:error, Map.t, integer} |
                                              {:redirect, String.t} |
                                              {:native_redirect, %{code: String.t}}
  def preauthorize(resource_owner, request) do
    case validate_response_type(request) do
      {:error, :invalid_response_type} -> unsupported_response_type(resource_owner, request)
      {:error, :missing_response_type} -> invalid_request(resource_owner, request)
      {:ok, token_module}              -> apply(token_module, :preauthorize, [resource_owner, request])
    end
  end

  @doc """
  Check ExOauth2Provider.Authorization.Code for usage.
  """
  @spec authorize(Ecto.Schema.t, Map.t) :: {:ok, String.t} |
                                           {:error, Map.t, integer} |
                                           {:redirect, String.t} |
                                           {:native_redirect, %{code: String.t}}
  def authorize(resource_owner, request) do
    case validate_response_type(request) do
      {:error, :invalid_response_type} -> unsupported_response_type(resource_owner, request)
      {:error, :missing_response_type} -> invalid_request(resource_owner, request)
      {:ok, token_module}              -> apply(token_module, :authorize, [resource_owner, request])
    end
  end

  @doc """
  Check ExOauth2Provider.Authorization.Code for usage.
  """
  @spec deny(Ecto.Schema.t, Map.t) :: {:error, Map.t, integer} |
                                      {:redirect, String.t}
  def deny(resource_owner, request) do
    case validate_response_type(request) do
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
    |> Response.error_response()
  end

  defp validate_response_type(%{"response_type" => response_type}) do
    ExOauth2Provider.Config.calculate_authorization_response_types()
    |> Keyword.fetch(String.to_atom(response_type))
    |> case do
      {:ok, authorization_module} -> {:ok, authorization_module}
      :error                      -> {:error, :invalid_response_type}
    end
  end
  defp validate_response_type(_), do: {:error, :missing_response_type}
end
