defmodule ExOauth2Provider.Authorization.DeviceCode do
  @moduledoc """
  This module is the glue for the various steps and integrates it into
  the authorization architecture that this package provides. It separates
  the concerns to simplify things.
  """
  alias Ecto.Schema
  alias ExOauth2Provider.Authorization.DeviceCode.DeviceAuthorization
  alias ExOauth2Provider.Authorization.DeviceCode.UserInteraction
  alias ExOauth2Provider.Authorization.Utils.Response

  # User Interaction Request - approve the grant with user code
  # https://datatracker.ietf.org/doc/html/rfc8628#section-3.3
  @spec authorize(Schema.t(), map(), keyword()) ::
          Response.authorization_success() | Response.error()
  def authorize(resource_owner, request, config \\ []) do
    UserInteraction.process_request(resource_owner, request, config)
  end

  # Device Authorization Request
  # https://tools.ietf.org/html/rfc8628#section-3.1
  @spec preauthorize(Schema.t(), map(), keyword()) ::
          Response.device_preauthorization_success() | Response.error()
  def preauthorize(_resource_owner, request, config \\ []) do
    DeviceAuthorization.process_request(request, config)
  end
end
