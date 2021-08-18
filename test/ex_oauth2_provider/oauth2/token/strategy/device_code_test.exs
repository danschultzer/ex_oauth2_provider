defmodule ExOauth2Provider.Token.DeviceCodeTest do
  use ExOauth2Provider.TestCase

  alias Dummy.OauthDeviceGrants.OauthDeviceGrant
  alias Dummy.OauthAccessTokens.OauthAccessToken
  alias ExOauth2Provider.{Config, Token}
  alias ExOauth2Provider.AccessTokens
  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}

  @config [otp_app: :ex_oauth2_provider]

  setup do
    application =
      Fixtures.application(
        uid: "abc123",
        scopes: "app:read app:write",
        secret: ""
      )

    owner = Fixtures.resource_owner()

    grant =
      Fixtures.device_grant(
        application_id: application.id,
        resource_owner_id: owner.id,
        user_code: nil
      )

    {
      :ok,
      %{
        application: application,
        grant: grant,
        owner: owner,
        polling_interval: Config.device_flow_polling_interval(@config)
      }
    }
  end

  describe "#grant/2 when request is valid" do
    test "it returns the access token and deletes the grant", context do
      %{application: application, grant: grant, owner: owner} = context

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :ok,
        %{
          access_token: access_token,
          expires: expires,
          refresh_token: refresh_token,
          scope: scope,
          token_type: token_type
        }
      } = Token.grant(request, @config)

      assert access_token =~ ~r/[a-z0-9]{32,}/i
      assert expires == Config.access_token_expires_in(@config)
      assert refresh_token =~ ~r/[a-z0-9]{32,}/i
      assert scope == ""
      assert token_type == "bearer"
      assert QueryHelpers.count(OauthDeviceGrant) == 0

      record = QueryHelpers.get_latest_inserted(OauthAccessToken)

      assert record.application_id == application.id
      assert record.expires_in == expires
      assert record.previous_refresh_token == ""
      assert record.refresh_token == refresh_token
      assert record.resource_owner_id == owner.id
      assert record.revoked_at == nil
      assert record.scopes == scope
      assert record.token == access_token
    end
  end

  describe "#grant/2 when device is polling too frequently" do
    test "it returns the slow_down error and updates the last polled timestamp", context do
      %{
        application: application,
        grant: grant,
        polling_interval: polling_interval
      } = context

      last_polled_at =
        QueryHelpers.timestamp(
          OauthDeviceGrant,
          :last_polled_at,
          seconds: -polling_interval
        )

      QueryHelpers.change!(grant, last_polled_at: last_polled_at)

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :error,
        %{error: :slow_down},
        :bad_request
      } = Token.grant(request, @config)

      grant = QueryHelpers.get_latest_inserted(OauthDeviceGrant)

      assert grant.last_polled_at > last_polled_at
    end
  end

  describe "#grant/2 when previous requests were received and polling rate is OK" do
    test "it does not block the request and behaves normally", context do
      %{
        application: application,
        grant: grant,
        polling_interval: polling_interval
      } = context

      last_polled_at =
        QueryHelpers.timestamp(
          OauthDeviceGrant,
          :last_polled_at,
          seconds: -(polling_interval + 1)
        )

      QueryHelpers.change!(grant, last_polled_at: last_polled_at)

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {:ok, _payload} = Token.grant(request, @config)
    end
  end

  describe "#grant/2 when the grant is not approved yet but still valid" do
    test "it returns the authorization_pending error and updates the last polled timestamp",
         context do
      %{application: application, grant: grant} = context
      original_last_polled_at = grant.last_polled_at

      QueryHelpers.change!(
        grant,
        resource_owner_id: nil,
        user_code: "still-waiting"
      )

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :error,
        %{error: :authorization_pending},
        :bad_request
      } = Token.grant(request, @config)

      grant = QueryHelpers.get_latest_inserted(OauthDeviceGrant)

      assert grant.last_polled_at > original_last_polled_at
    end
  end

  describe "#grant/2 when the device code has expired" do
    test "it returns the expired_token error and destroys the grant", context do
      %{application: application, grant: grant} = context

      inserted_at =
        QueryHelpers.timestamp(
          OauthDeviceGrant,
          :inserted_at,
          seconds: -Config.access_token_expires_in(@config)
        )

      QueryHelpers.change!(grant, inserted_at: inserted_at)

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :error,
        %{error: :expired_token},
        :bad_request
      } = Token.grant(request, @config)

      assert QueryHelpers.count(OauthDeviceGrant) == 0
    end
  end

  describe "#grant/2 when device code is invalid" do
    test "it returns the invalid_grant error", %{application: application} do
      request = %{
        "client_id" => application.uid,
        "device_code" => "this-wont-match",
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :error,
        %{
          error: :invalid_grant,
          error_description: message
        },
        :bad_request
      } = Token.grant(request, @config)

      assert message =~ ~r/grant is invalid/i
    end
  end

  describe "#grant/2 when device code is missing" do
    test "it returns the invalid_request error", %{application: application} do
      request = %{
        "client_id" => application.uid,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :error,
        %{
          error: :invalid_request,
          error_description: message
        },
        :bad_request
      } = Token.grant(request, @config)

      assert message =~ ~r/missing required param device_code/i
    end
  end

  describe "#grant/2 when client_id is invalid" do
    test "it returns the invalid_client error", %{grant: grant} do
      request = %{
        "client_id" => "this-is-not-matching",
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :error,
        %{
          error: :invalid_client,
          error_description: message
        },
        :unauthorized
      } = Token.grant(request, @config)

      assert message =~ ~r/unknown client/i
    end
  end

  describe "#grant/2 when client_id is missing" do
    test "it returns the invalid_request error" do
      request = %{
        "device_code" => "abc123",
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :error,
        %{
          error: :invalid_request,
          error_description: message
        },
        :bad_request
      } = Token.grant(request, @config)

      assert message =~ ~r/missing required param client_id/i
    end
  end

  describe "#grant/2 when client_id and device_code is missing" do
    test "it returns the invalid_request error" do
      request = %{"grant_type" => "urn:ietf:params:oauth:grant-type:device_code"}

      {
        :error,
        %{
          error: :invalid_request,
          error_description: message
        },
        :bad_request
      } = Token.grant(request, @config)

      assert message =~ ~r/missing required param client_id, device_code/i
    end
  end

  describe "#grant/2 when application has no scopes" do
    test "it creates the token with the configured default scope", context do
      %{application: application, grant: grant} = context

      QueryHelpers.change!(application, scopes: "")

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {:ok, _payload} = Token.grant(request, @config)

      default_scopes =
        @config
        |> Config.default_scopes()
        |> Enum.join(",")

      access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

      assert access_token.scopes == default_scopes
    end
  end

  describe "#grant/2 when client_secret is given and valid" do
    test "it behaves like normal", %{application: application, grant: grant} do
      application = QueryHelpers.change!(application, secret: "secret")

      request = %{
        "client_id" => application.uid,
        "client_secret" => application.secret,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {:ok, _payload} = Token.grant(request, @config)
    end
  end

  describe "#grant/2 when client_secret is given and invalid" do
    test "it returns invalid_client error", context do
      %{application: application, grant: grant} = context

      request = %{
        "client_id" => application.uid,
        "client_secret" => "invalid-secret",
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {
        :error,
        %{error: :invalid_client},
        :unauthorized
      } = Token.grant(request, @config)
    end
  end

  describe "#grant/2 when valid scopes are given" do
    test "it adds them to the token", %{application: application, grant: grant} do
      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
        "scope" => "app:read"
      }

      {:ok, _payload} = Token.grant(request, @config)
      access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

      assert access_token.scopes == "app:read"
    end
  end

  describe "#grant/2 when invalid scopes are given" do
    test "it returns invalid_scope error", context do
      %{application: application, grant: grant} = context

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
        "scope" => "ability_to_delete_all_the_things!"
      }

      {
        :error,
        %{
          error: :invalid_scope,
          error_description: message
        },
        :bad_request
      } = Token.grant(request, @config)

      assert message =~ ~r/scope is invalid/i
    end
  end

  describe "#grant/2 when configured to not use refresh token" do
    test "it does not set the refresh token", context do
      %{application: application, grant: grant} = context
      modified_config = Keyword.put(@config, :use_refresh_token, false)

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {:ok, payload} = Token.grant(request, modified_config)

      record = QueryHelpers.get_latest_inserted(OauthAccessToken)

      assert record.refresh_token == nil
      refute record.token == nil
      assert record.refresh_token == payload.refresh_token
      assert record.token == payload.access_token
    end
  end

  describe "#grant/2 when a valid access token already exists" do
    test "it returns the existing token and deletes the grant", context do
      %{application: application, grant: grant, owner: owner} = context

      existing_token =
        Fixtures.access_token(
          application: application,
          resource_owner: owner,
          scopes: ""
        )

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {:ok, payload} = Token.grant(request, @config)

      assert existing_token.token == payload.access_token
      assert QueryHelpers.count(OauthAccessToken) == 1
      assert QueryHelpers.count(OauthDeviceGrant) == 0
    end
  end

  describe "#grant/2 when a revoked access token already exists" do
    test "it creates a new one", context do
      %{application: application, grant: grant, owner: owner} = context

      revoked_token =
        [application: application, resource_owner: owner, scopes: ""]
        |> Fixtures.access_token()
        |> AccessTokens.revoke!()

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {:ok, payload} = Token.grant(request, @config)

      refute revoked_token.token == payload.access_token
      assert QueryHelpers.count(OauthAccessToken) == 2
    end
  end

  describe "#grant/2 when an expired access token already exists" do
    test "it creates a new one", context do
      %{application: application, grant: grant, owner: owner} = context

      expired_token =
        Fixtures.access_token(
          application: application,
          resource_owner: owner,
          scopes: ""
        )

      inserted_at =
        QueryHelpers.timestamp(
          OauthAccessToken,
          :inserted_at,
          seconds: -Config.access_token_expires_in(@config)
        )

      QueryHelpers.change!(expired_token, inserted_at: inserted_at)

      request = %{
        "client_id" => application.uid,
        "device_code" => grant.device_code,
        "grant_type" => "urn:ietf:params:oauth:grant-type:device_code"
      }

      {:ok, payload} = Token.grant(request, @config)

      refute expired_token.token == payload.access_token
      assert QueryHelpers.count(OauthAccessToken) == 2
    end
  end
end
