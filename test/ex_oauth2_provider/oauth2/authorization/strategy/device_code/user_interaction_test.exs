defmodule ExOauth2Provider.Authorization.DeviceCode.UserInteractionTest do
  use ExOauth2Provider.TestCase

  alias Dummy.OauthDeviceGrants.OauthDeviceGrant
  alias ExOauth2Provider.Authorization.DeviceCode.UserInteraction
  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}

  @config [otp_app: :ex_oauth2_provider]

  setup do
    application =
      Fixtures.application(
        uid: "abc123",
        scopes: "app:read app:write"
      )

    device_grant = Fixtures.device_grant(application_id: application.id)
    owner = Fixtures.resource_owner()

    {
      :ok,
      %{
        application: application,
        device_grant: device_grant,
        owner: owner
      }
    }
  end

  describe "#authorize/3" do
    test "updates the grant and responds with :ok tuple with the grant", context do
      %{device_grant: device_grant, owner: owner} = context

      request = %{
        "response_type" => "device_code",
        "user_code" => device_grant.user_code
      }

      {:ok, updated_grant} = UserInteraction.process_request(owner, request, @config)

      assert updated_grant.id == device_grant.id
      assert updated_grant.user_code == nil
      assert updated_grant.resource_owner_id == owner.id
    end

    test "returns invalid_user_code when user_code is missing", context do
      %{owner: owner} = context

      request = %{"response_type" => "device_code"}

      {
        :error,
        %{
          error: error_code,
          error_description: message
        },
        status_code
      } = UserInteraction.process_request(owner, request, @config)

      assert error_code == :user_code_missing
      assert status_code == :bad_request
      assert message =~ ~r/missing the required param user_code/i
    end

    test "returns invalid_user_code when no grant is found", %{owner: owner} do
      request = %{
        "response_type" => "device_code",
        "user_code" => "non-existent-code"
      }

      {
        :error,
        %{
          error: error_code,
          error_description: message
        },
        status_code
      } = UserInteraction.process_request(owner, request, @config)

      assert error_code == :invalid_user_code
      assert status_code == :unprocessable_entity
      assert message =~ ~r/code is invalid/i
    end

    test "returns expired_user_code when the grant is expired", context do
      %{device_grant: device_grant, owner: owner} = context

      inserted_at =
        QueryHelpers.timestamp(
          OauthDeviceGrant,
          :inserted_at,
          seconds: -device_grant.expires_in
        )

      QueryHelpers.change!(device_grant, inserted_at: inserted_at)

      request = %{
        "response_type" => "device_code",
        "user_code" => device_grant.user_code
      }

      {
        :error,
        %{
          error: error_code,
          error_description: message
        },
        status_code
      } = UserInteraction.process_request(owner, request, @config)

      assert error_code == :expired_user_code
      assert status_code == :unprocessable_entity
      assert message =~ ~r/user_code has expired/i
    end

    test "returns invalid_request when the DB update fails unexpectedly", context do
      %{device_grant: device_grant} = context
      non_existent_owner = %OauthDeviceGrant{id: "blah"}

      request = %{
        "response_type" => "device_code",
        "user_code" => device_grant.user_code
      }

      {
        :error,
        %{
          error: error_code,
          error_description: message
        },
        status_code
      } = UserInteraction.process_request(non_existent_owner, request, @config)

      assert error_code == :invalid_owner
      assert status_code == :unprocessable_entity
      assert message =~ ~r/owner is invalid/i
    end
  end
end
