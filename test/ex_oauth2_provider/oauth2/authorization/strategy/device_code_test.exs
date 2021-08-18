defmodule ExOauth2Provider.Authorization.DeviceCodeTest do
  use ExOauth2Provider.TestCase

  alias Dummy.OauthDeviceGrants.OauthDeviceGrant
  alias ExOauth2Provider.Authorization
  alias ExOauth2Provider.Test.Fixtures

  @config [otp_app: :ex_oauth2_provider]

  setup do
    application =
      Fixtures.application(
        uid: "abc123",
        scopes: "app:read app:write"
      )

    {:ok, %{application: application}}
  end

  describe "#authorize/3" do
    test "invokes the user interaction and approves the device grant", context do
      %{application: application} = context
      device_grant = Fixtures.device_grant(application_id: application.id)
      owner = Fixtures.resource_owner()

      request = %{
        "response_type" => "device_code",
        "user_code" => device_grant.user_code
      }

      {:ok, %OauthDeviceGrant{}} = Authorization.authorize(owner, request, @config)
    end
  end

  describe "#preauthorize/3" do
    test "invokes the device authorization and creats the device grant", context do
      %{application: application} = context

      request = %{
        "client_id" => application.uid,
        "response_type" => "device_code"
      }

      {:ok,
       %{
         device_code: _device_code,
         expires_in: _expires_in,
         interval: _interval,
         user_code: _user_code,
         verification_uri: _verification_uri
       }} = Authorization.preauthorize(nil, request, @config)
    end
  end
end
