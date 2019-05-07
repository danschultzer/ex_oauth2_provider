defmodule ExOauth2Provider.ApplicationsTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.{AccessTokens, Applications}
  alias Dummy.{OauthApplications.OauthApplication, OauthAccessTokens.OauthAccessToken}

  @valid_attrs    %{name: "Application", redirect_uri: "https://example.org/endpoint"}
  @invalid_attrs  %{}

  setup do
    {:ok, %{user: Fixtures.resource_owner()}}
  end

  test "get_applications_for/1", %{user: user} do
    assert {:ok, application} = Applications.create_application(user, @valid_attrs)
    assert {:ok, _application} = Applications.create_application(Fixtures.resource_owner(), @valid_attrs)

    assert [%OauthApplication{id: id}] = Applications.get_applications_for(user)
    assert id == application.id
  end

  test "get_application!/1", %{user: user} do
    assert {:ok, application} = Applications.create_application(user, @valid_attrs)

    assert %OauthApplication{id: id} = Applications.get_application!(application.uid)
    assert id == application.id
  end

  test "get_application/1", %{user: user} do
    assert {:ok, application} = Applications.create_application(user, @valid_attrs)

    assert %OauthApplication{id: id} = Applications.get_application(application.uid)
    assert id == application.id
  end

  test "get_application_for!/1", %{user: user} do
    {:ok, application} = Applications.create_application(user, @valid_attrs)

    assert %OauthApplication{id: id} = Applications.get_application_for!(user, application.uid)
    assert id == application.id

    assert_raise Ecto.NoResultsError, fn ->
      Applications.get_application_for!(Fixtures.resource_owner(), application.uid)
    end
  end

  test "get_authorized_applications_for/1", %{user: user} do
    application = Fixtures.application()
    application2 = Fixtures.application(uid: "newapp")
    assert {:ok, token} = AccessTokens.create_token(user, %{application: application})
    assert {:ok, _token} = AccessTokens.create_token(user, %{application: application2})

    assert Applications.get_authorized_applications_for(user) == [application, application2]
    assert Applications.get_authorized_applications_for(Fixtures.resource_owner()) == []

    AccessTokens.revoke(token)
    assert Applications.get_authorized_applications_for(user) == [application2]
  end

  describe "create_application/2" do
    test "with valid attributes", %{user: user} do
      assert {:ok, application} = Applications.create_application(user, @valid_attrs)
      assert application.name == @valid_attrs.name
      assert application.scopes == "public"
    end

    test "with invalid attributes", %{user: user} do
      assert {:error, changeset} = Applications.create_application(user, @invalid_attrs)
      assert changeset.errors[:name]
    end

    test "with invalid scopes", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "invalid"})

      assert {:error, %Ecto.Changeset{}} = Applications.create_application(user, attrs)
    end

    test "with limited scopes", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "read write"})

      assert {:ok, application} = Applications.create_application(user, attrs)
      assert application.scopes == "read write"
    end

    test "adds random secret", %{user: user} do
      {:ok, application} = Applications.create_application(user, @valid_attrs)
      {:ok, application2} = Applications.create_application(user, @valid_attrs)

      assert application.secret != application2.secret
    end

    test "permits empty string secret", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{secret: ""})

      assert {:ok, application} = Applications.create_application(user, attrs)
      assert application.secret == ""
    end

    test "adds random uid", %{user: user} do
      {:ok, application} = Applications.create_application(user, @valid_attrs)
      {:ok, application2} = Applications.create_application(user, @valid_attrs)
      assert application.uid != application2.uid
    end

    test "adds custom uid", %{user: user} do
      {:ok, application} = Applications.create_application(user, Map.merge(@valid_attrs, %{uid: "custom"}))
      assert application.uid == "custom"
    end

    test "adds custom secret", %{user: user} do
      {:ok, application} = Applications.create_application(user, Map.merge(@valid_attrs, %{secret: "custom"}))
      assert application.secret == "custom"
    end
  end

  test "update_application/2", %{user: user} do
    assert {:ok, application} = Applications.create_application(user, @valid_attrs)

    assert {:ok, application} = Applications.update_application(application, %{name: "Updated App"})
    assert application.name == "Updated App"
  end

  test "delete_application/1", %{user: user} do
    {:ok, application} = Applications.create_application(user, @valid_attrs)

    assert {:ok, _appliction} = Applications.delete_application(application)
    assert_raise Ecto.NoResultsError, fn ->
      Applications.get_application!(application.uid)
    end
  end

  test "revoke_all_access_tokens_for/2", %{user: user} do
    application = Fixtures.application()
    {:ok, token} = AccessTokens.create_token(user, %{application: application})
    {:ok, token2} = AccessTokens.create_token(user, %{application: application})
    {:ok, token3} = AccessTokens.create_token(user, %{application: application})
    AccessTokens.revoke(token3)

    assert {:ok, objects} = Applications.revoke_all_access_tokens_for(application, user)
    assert Enum.count(objects) == 2

    assert AccessTokens.is_revoked?(ExOauth2Provider.repo.get!(OauthAccessToken, token.id))
    assert AccessTokens.is_revoked?(ExOauth2Provider.repo.get!(OauthAccessToken, token2.id))
  end
end
