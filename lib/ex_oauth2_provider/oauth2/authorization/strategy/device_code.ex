defmodule ExOauth2Provider.Authorization.DeviceCode do
  alias ExOauth2Provider.Authorization.DeviceCode.DeviceAuthorization
  alias ExOauth2Provider.Authorization.DeviceCode.UserInteraction

  # NOTE: This module is the glue for the various steps and integrates it into
  # the authorization architecture that this package provides. It separates
  # the concerns to simplify things.

  # User Interaction Request - approve the grant with user code
  # https://datatracker.ietf.org/doc/html/rfc8628#section-3.3
  def authorize(resource_owner, request, config \\ []) do
    UserInteraction.process_request(resource_owner, request, config)
  end

  # Device Authorization Request
  # https://tools.ietf.org/html/rfc8628#section-3.1
  def preauthorize(_resource_owner, request, config \\ []) do
    DeviceAuthorization.process_request(request, config)
  end
end
