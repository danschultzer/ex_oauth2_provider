defmodule ExOauth2Provider.Authorization.DeviceCode.DeviceAuthorizationTest do
  use ExOauth2Provider.TestCase

  alias Dummy.OauthDeviceGrants.OauthDeviceGrant
  alias ExOauth2Provider.Config
  alias ExOauth2Provider.Authorization.DeviceCode.DeviceAuthorization
  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}

  @config [otp_app: :ex_oauth2_provider]

  setup do
    application =
      Fixtures.application(
        uid: "abc123",
        scopes: "app:read app:write"
      )

    {:ok, %{application: application}}
  end

  describe "#process_request/2" do
    test "returns :ok tuple when request is valid", %{application: application} do
      request = %{
        "client_id" => application.uid,
        "response_type" => "device_code"
      }

      {:ok,
       %{
         device_code: device_code,
         expires_in: expires_in,
         interval: interval,
         user_code: user_code,
         verification_uri: verification_uri
       }} = DeviceAuthorization.process_request(request, @config)

      assert device_code =~ ~r/[a-z0-9=_-]{44}/i
      assert expires_in == Config.authorization_code_expires_in(@config)
      assert interval == Config.device_flow_polling_interval(@config)
      assert user_code =~ ~r/[A-Z0-9]{8}/
      refute verification_uri === nil

      device_grant = QueryHelpers.get_latest_inserted(OauthDeviceGrant)

      assert device_code == device_grant.device_code
      assert expires_in == device_grant.expires_in
      assert user_code == device_grant.user_code
      assert device_grant.scopes == ""
      assert device_grant.application_id == application.id
      assert device_grant.resource_owner_id == nil
    end

    test "returns :error tuple when client_id is not given" do
      request = %{"response_type" => "device_code"}

      {
        :error,
        %{
          error: :invalid_request,
          error_description: message
        },
        :bad_request
      } = DeviceAuthorization.process_request(request, @config)

      assert message =~ ~r/missing required param client_id/i
    end

    test "returns :error tuple when client_id is not found" do
      request = %{
        "client_id" => "this-is-non-existent",
        "response_type" => "device_code"
      }

      {
        :error,
        %{
          error: :invalid_client,
          error_description: message
        },
        :unauthorized
      } = DeviceAuthorization.process_request(request, @config)

      assert message =~ ~r/unknown client/i
    end

    test "accepts optional scopes when given", %{application: application} do
      request = %{
        "client_id" => application.uid,
        "response_type" => "device_code",
        "scope" => "app:read"
      }

      {:ok, _payload} = DeviceAuthorization.process_request(request, @config)
      device_grant = QueryHelpers.get_latest_inserted(OauthDeviceGrant)

      assert device_grant.scopes == "app:read"
    end

    test "returns :error tuple when scope is invalid", %{application: application} do
      request = %{
        "client_id" => application.uid,
        "response_type" => "device_code",
        "scope" => "app:read app:write BAD:THING"
      }

      {
        :error,
        %{
          error: :invalid_scope,
          error_description: message
        },
        :bad_request
      } = DeviceAuthorization.process_request(request, @config)

      assert message =~ ~r/scope is invalid/i
    end

    test "deletes expired grants during successful grant creation", %{application: application} do
      device_grant = Fixtures.device_grant()

      inserted_at =
        QueryHelpers.timestamp(
          OauthDeviceGrant,
          :inserted_at,
          seconds: -device_grant.expires_in
        )

      QueryHelpers.change!(device_grant, inserted_at: inserted_at)

      request = %{
        "client_id" => application.uid,
        "response_type" => "device_code"
      }

      {:ok, _payload} = DeviceAuthorization.process_request(request, @config)
      latest_device_grant = QueryHelpers.get_latest_inserted(OauthDeviceGrant)

      assert device_grant.id != latest_device_grant.id
      assert QueryHelpers.count(OauthDeviceGrant) == 1
    end
  end

  describe "#process_request/2 when application has no scopes" do
    setup %{application: application} do
      application = QueryHelpers.change!(application, scopes: "")

      %{application: application}
    end

    test "it allows generic scopes", %{application: application} do
      request = %{
        "client_id" => application.uid,
        "response_type" => "device_code",
        "scope" => "read"
      }

      {:ok, _payload} = DeviceAuthorization.process_request(request, @config)
    end

    test "it denies granular scopes", %{application: application} do
      request = %{
        "client_id" => application.uid,
        "response_type" => "device_code",
        "scope" => "app:read"
      }

      {:error, %{error: :invalid_scope}, :bad_request} =
        DeviceAuthorization.process_request(request, @config)
    end
  end

  describe "#process_request when values are configured" do
    test "it generates the grant based on the config", context do
      %{application: application} = context

      request = %{
        "client_id" => application.uid,
        "response_type" => "device_code"
      }

      custom_config =
        Keyword.merge(
          @config,
          authorization_code_expires_in: 60,
          device_flow_device_code_length: 10,
          device_flow_polling_interval: 30,
          device_flow_user_code_length: 4
        )

      {:ok,
       %{
         device_code: device_code,
         expires_in: expires_in,
         interval: interval,
         user_code: user_code
       }} = DeviceAuthorization.process_request(request, custom_config)

      # Base64 encoded 10 char string is 16 long.
      assert String.length(device_code) == 16
      assert expires_in == 60
      assert interval == 30
      assert String.length(user_code) == 4
    end
  end
end
