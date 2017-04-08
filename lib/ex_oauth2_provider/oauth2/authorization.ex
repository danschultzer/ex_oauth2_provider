defmodule ExOauth2Provider.Authorization do
  @moduledoc """
  Handler for dealing with authorization flow.
  """
  alias ExOauth2Provider.Authorization.Code
  alias ExOauth2Provider.Util.Error

  def preauthorize(resource_owner, %{"response_type" => "code"} = request),
    do: Code.preauthorize(resource_owner, request)
  def preauthorize(_, %{"response_type" => _}), do: Error.unsupported_response_type()
  def preauthorize(_, _), do: Error.invalid_request()

  def authorize(resource_owner, %{"response_type" => "code"} = request),
    do: Code.authorize(resource_owner, request)
  def authorize(_, %{"response_type" => _}), do: Error.unsupported_response_type()
  def authorize(_, _), do: Error.invalid_request()

  def deny(resource_owner, %{"response_type" => "code"} = request),
    do: Code.deny(resource_owner, request)
  def deny(_, %{"response_type" => _}), do: Error.unsupported_response_type()
  def deny(_, _), do: Error.invalid_request()
end
