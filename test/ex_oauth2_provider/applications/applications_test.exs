defmodule ExOauth2Provider.ApplicationsTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.{AccessTokens, Applications}
  alias Dummy.{OauthApplications.OauthApplication, OauthAccessTokens.OauthAccessToken, Repo}

  @valid_attrs %{name: "Application", redirect_uri: "https://example.org/endpoint"}
  @invalid_attrs %{}

  setup do
    {:ok, %{user: Fixtures.resource_owner()}}
  end

  test "get_applications_for/2", %{user: user} do
    assert {:ok, application} =
             Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

    assert {:ok, _application} =
             Applications.create_application(Fixtures.resource_owner(), @valid_attrs,
               otp_app: :ex_oauth2_provider
             )

    assert [%OauthApplication{id: id}] =
             Applications.get_applications_for(user, otp_app: :ex_oauth2_provider)

    assert id == application.id
  end

  test "get_application!/2", %{user: user} do
    assert {:ok, application} =
             Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

    assert %OauthApplication{id: id} =
             Applications.get_application!(application.uid, otp_app: :ex_oauth2_provider)

    assert id == application.id
  end

  test "get_application/2", %{user: user} do
    assert {:ok, application} =
             Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

    assert %OauthApplication{id: id} =
             Applications.get_application(application.uid, otp_app: :ex_oauth2_provider)

    assert id == application.id
  end

  test "get_application_for!/2", %{user: user} do
    {:ok, application} =
      Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

    assert %OauthApplication{id: id} =
             Applications.get_application_for!(user, application.uid, otp_app: :ex_oauth2_provider)

    assert id == application.id

    assert_raise Ecto.NoResultsError, fn ->
      Applications.get_application_for!(Fixtures.resource_owner(), application.uid,
        otp_app: :ex_oauth2_provider
      )
    end
  end

  test "get_authorized_applications_for/2", %{user: user} do
    application = Fixtures.application()
    application2 = Fixtures.application(uid: "newapp")

    assert {:ok, token} =
             AccessTokens.create_token(user, %{application: application},
               otp_app: :ex_oauth2_provider
             )

    assert {:ok, _token} =
             AccessTokens.create_token(user, %{application: application2},
               otp_app: :ex_oauth2_provider
             )

    assert Applications.get_authorized_applications_for(user, otp_app: :ex_oauth2_provider) == [
             application,
             application2
           ]

    assert Applications.get_authorized_applications_for(Fixtures.resource_owner(),
             otp_app: :ex_oauth2_provider
           ) == []

    AccessTokens.revoke(token, otp_app: :ex_oauth2_provider)

    assert Applications.get_authorized_applications_for(user, otp_app: :ex_oauth2_provider) == [
             application2
           ]
  end

  describe "create_application/3" do
    test "with valid attributes", %{user: user} do
      assert {:ok, application} =
               Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

      assert application.name == @valid_attrs.name
      assert application.scopes == "public"
    end

    test "with invalid attributes", %{user: user} do
      assert {:error, changeset} =
               Applications.create_application(user, @invalid_attrs, otp_app: :ex_oauth2_provider)

      assert changeset.errors[:name]
    end

    test "with invalid scopes", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "invalid"})

      assert {:error, %Ecto.Changeset{}} =
               Applications.create_application(user, attrs, otp_app: :ex_oauth2_provider)
    end

    test "with limited scopes", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "read write"})

      assert {:ok, application} =
               Applications.create_application(user, attrs, otp_app: :ex_oauth2_provider)

      assert application.scopes == "read write"
    end

    test "adds random secret", %{user: user} do
      {:ok, application} =
        Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

      {:ok, application2} =
        Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

      assert application.secret != application2.secret
    end

    test "permits empty string secret", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{secret: ""})

      assert {:ok, application} =
               Applications.create_application(user, attrs, otp_app: :ex_oauth2_provider)

      assert application.secret == ""
    end

    test "adds random uid", %{user: user} do
      {:ok, application} =
        Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

      {:ok, application2} =
        Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

      assert application.uid != application2.uid
    end

    test "adds custom uid", %{user: user} do
      {:ok, application} =
        Applications.create_application(user, Map.merge(@valid_attrs, %{uid: "custom"}),
          otp_app: :ex_oauth2_provider
        )

      assert application.uid == "custom"
    end

    test "adds custom secret", %{user: user} do
      {:ok, application} =
        Applications.create_application(user, Map.merge(@valid_attrs, %{secret: "custom"}),
          otp_app: :ex_oauth2_provider
        )

      assert application.secret == "custom"
    end
  end

  test "update_application/3", %{user: user} do
    assert {:ok, application} =
             Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

    assert {:ok, application} =
             Applications.update_application(application, %{name: "Updated App"},
               otp_app: :ex_oauth2_provider
             )

    assert application.name == "Updated App"
  end

  test "delete_application/2", %{user: user} do
    {:ok, application} =
      Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

    assert {:ok, _appliction} =
             Applications.delete_application(application, otp_app: :ex_oauth2_provider)

    assert_raise Ecto.NoResultsError, fn ->
      Applications.get_application!(application.uid, otp_app: :ex_oauth2_provider)
    end
  end

  test "revoke_all_access_tokens_for/3", %{user: user} do
    application = Fixtures.application()

    {:ok, token} =
      AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)

    {:ok, token2} =
      AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)

    {:ok, token3} =
      AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)

    AccessTokens.revoke(token3)

    assert {:ok, objects} =
             Applications.revoke_all_access_tokens_for(application, user,
               otp_app: :ex_oauth2_provider
             )

    assert Enum.count(objects) == 2

    assert AccessTokens.is_revoked?(Repo.get!(OauthAccessToken, token.id))
    assert AccessTokens.is_revoked?(Repo.get!(OauthAccessToken, token2.id))
  end
end
