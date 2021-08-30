defmodule ExOauth2Provider.DeviceGrantsTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.DeviceGrants
  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.Test.QueryHelpers
  alias Dummy.{OauthDeviceGrants.OauthDeviceGrant, Repo, Users.User}

  @config [otp_app: :ex_oauth2_provider]

  setup do
    application = Fixtures.application()

    {:ok, %{application: application}}
  end

  describe "#authorize/3" do
    test "updates the given grant and returns the result tuple", context do
      %{application: application} = context

      grant = Fixtures.device_grant(application: application)
      user = Fixtures.resource_owner()

      {:ok, updated_grant} = DeviceGrants.authorize(grant, user, @config)

      assert updated_grant.id == grant.id
      assert updated_grant.resource_owner_id == user.id
      assert updated_grant.user_code == nil
    end

    test "returns an error tuple when the changeset is invalid", context do
      %{application: application} = context

      grant = Fixtures.device_grant(application: application)
      user = %User{id: "abc"}

      {:error, _changeset} = DeviceGrants.authorize(grant, user, @config)
    end
  end

  describe "#authorized?/1" do
    test "returns true when the given schema has been authorized" do
      grant = %OauthDeviceGrant{resource_owner_id: "abc", user_code: nil}

      assert DeviceGrants.authorized?(grant) == true
    end

    test "returns false when the given schema is not authorized" do
      grant = %OauthDeviceGrant{resource_owner_id: nil, user_code: "abc"}

      assert DeviceGrants.authorized?(grant) == false
    end
  end

  describe "#create_grant/3" do
    test "inserts a new record and returns the result tuple", context do
      %{application: application} = context

      attrs = %{
        "device_code" => "dc",
        "expires_in" => 10,
        "user_code" => "uc"
      }

      {:ok, grant} = DeviceGrants.create_grant(application, attrs, @config)

      refute grant.id == nil
      assert grant.device_code == "dc"
      assert grant.expires_in == 10
      assert grant.last_polled_at == nil
      # Default behavior when not specified
      assert grant.scopes == "public"
      assert grant.user_code == "uc"
    end

    test "accepts valid scopes", %{application: application} do
      attrs = %{
        "device_code" => "dc",
        "expires_in" => 10,
        "scopes" => "read",
        "user_code" => "uc"
      }

      {:ok, grant} = DeviceGrants.create_grant(application, attrs, @config)

      assert grant.scopes == "read"
    end

    test "returns an error tuple when the changeset is invalid", context do
      %{application: application} = context
      {:error, _changeset} = DeviceGrants.create_grant(application, %{}, @config)
    end
  end

  describe "#delete_expired/1" do
    test "deletes all expired grants and returns the result tuple", context do
      %{application: application} = context

      grant = Fixtures.device_grant(application: application)

      inserted_at =
        QueryHelpers.timestamp(
          OauthDeviceGrant,
          :inserted_at,
          seconds: -grant.expires_in
        )

      QueryHelpers.change!(grant, inserted_at: inserted_at)

      {1, nil} = DeviceGrants.delete_expired(@config)
      assert QueryHelpers.count(OauthDeviceGrant) == 0
    end
  end

  describe "#delete!/1" do
    test "deletes the grant and returns it", %{application: application} do
      grant = Fixtures.device_grant(application: application)

      deleted_grant = DeviceGrants.delete!(grant, @config)

      assert deleted_grant.id == grant.id
      assert QueryHelpers.count(OauthDeviceGrant) == 0
    end

    test "raises an error when the changeset is invalid" do
      assert_raise Ecto.StaleEntryError, fn ->
        DeviceGrants.delete!(%OauthDeviceGrant{id: 123}, @config)
      end
    end
  end

  describe "#find_by_application_and_device_code/3" do
    test "returns the matching DeviceGrant", %{application: application} do
      grant = Fixtures.device_grant(application: application)

      found_grant =
        DeviceGrants.find_by_application_and_device_code(
          application,
          grant.device_code,
          @config
        )

      assert grant.id == found_grant.id
    end

    test "returns the nil when no matching grant exists", %{application: application} do
      result =
        DeviceGrants.find_by_application_and_device_code(
          application,
          "foo",
          @config
        )

      assert result == nil
    end
  end

  describe "#find_by_user_code/2" do
    test "returns the grant matching the user code", %{application: application} do
      grant = Fixtures.device_grant(application: application)

      found_grant = DeviceGrants.find_by_user_code(grant.user_code, @config)

      assert grant.id == found_grant.id
    end

    test "returns the nil when no matching grant exists" do
      result = DeviceGrants.find_by_user_code("foo", @config)

      assert result == nil
    end
  end

  describe "#update_last_polled_at!/2" do
    test "updates last polled at timestamp and returns the updated schema", context do
      %{application: application} = context
      grant = Fixtures.device_grant(application: application)
      assert grant.last_polled_at == nil

      grant = DeviceGrants.update_last_polled_at!(grant, @config)

      refute grant.last_polled_at == nil
    end

    test "raises an error when the changeset is invalid", context do
      %{application: application} = context

      grant =
        [application: application]
        |> Fixtures.device_grant()
        |> DeviceGrants.delete!(@config)

      assert_raise Ecto.StaleEntryError, fn ->
        DeviceGrants.update_last_polled_at!(grant, @config)
      end
    end
  end
end
