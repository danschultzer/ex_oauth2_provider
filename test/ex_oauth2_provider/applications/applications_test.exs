defmodule ExOauth2Provider.ApplicationsTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Authorization.Utils.Pkce
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

  describe "load_application/3" do
    setup %{user: user} do
      {:ok, application} =
        Applications.create_application(user, @valid_attrs, otp_app: :ex_oauth2_provider)

      {:ok, application: application}
    end

    test "secret is required when present in application", %{application: application} do
      assert %OauthApplication{id: id} =
               Applications.load_application(
                 application.uid,
                 {:client_secret, application.secret},
                 otp_app: :ex_oauth2_provider
               )

      assert nil ==
               Applications.load_application(application.uid, {:client_secret, ""},
                 otp_app: :ex_oauth2_provider
               )

      assert id == application.id
    end

    test "secret can be optionally not required", %{application: application} do
      assert application.secret != ""

      assert %OauthApplication{id: id} =
               Applications.load_application(application.uid, {:client_secret, :not_required},
                 otp_app: :ex_oauth2_provider
               )

      assert id == application.id
    end

    test "loading via code verifier", %{application: application} do
      code_verifier = "this_is_the_code_verifier"
      code_challenge = Pkce.generate_code_challenge(code_verifier, "S256")
      Pkce.store(application.uid, code_challenge)

      assert %OauthApplication{id: id} =
               Applications.load_application(
                 application.uid,
                 {:code_verifier, code_verifier, "S256"},
                 otp_app: :ex_oauth2_provider
               )

      assert id == application.id
    end
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

    objects =
      Applications.revoke_all_access_tokens_for(application, user, otp_app: :ex_oauth2_provider)

    assert [{:ok, _object} | _] = objects

    assert Enum.count(objects) == 2

    assert AccessTokens.is_revoked?(Repo.get!(OauthAccessToken, token.id))
    assert AccessTokens.is_revoked?(Repo.get!(OauthAccessToken, token2.id))
  end
end
