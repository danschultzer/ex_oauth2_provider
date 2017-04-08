defmodule ExOauth2Provider.Authorization do
  @moduledoc """
  Handler for dealing with authorization flow.
  """
  alias ExOauth2Provider.Authorization.Code
  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Authorization.Utils
  alias ExOauth2Provider.Authorization.Utils.Response

  @doc false
  def preauthorize(resource_owner, request) do
    case request do
      %{"response_type" => "code"} -> Code.preauthorize(resource_owner, request)
      %{"response_type" => _}      -> unsupported_response_type(resource_owner, request)
      _                            -> invalid_request(resource_owner, request)
    end
  end

  @doc false
  def authorize(resource_owner, request) do
    case request do
      %{"response_type" => "code"} -> Code.authorize(resource_owner, request)
      %{"response_type" => _}      -> unsupported_response_type(resource_owner, request)
      _                            -> invalid_request(resource_owner, request)
    end
  end

  @doc false
  def deny(resource_owner, request) do
    case request do
      %{"response_type" => "code"} -> Code.deny(resource_owner, request)
      %{"response_type" => _}      -> unsupported_response_type(resource_owner, request)
      _                            -> invalid_request(resource_owner, request)
    end
  end

  @doc false
  defp unsupported_response_type(resource_owner, request),
    do: handle_error_response(resource_owner, request, Error.unsupported_response_type())

  @doc false
  defp invalid_request(resource_owner, request),
    do: handle_error_response(resource_owner, request, Error.invalid_request())

  @doc false
  defp handle_error_response(resource_owner, request, error) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> Error.add_error(error)
    |> Response.error_response
  end
end
