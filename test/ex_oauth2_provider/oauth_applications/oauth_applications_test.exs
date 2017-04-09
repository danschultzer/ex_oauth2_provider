defmodule ExOauth2Provider.OauthApplicationsTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Test.Fixture

  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthApplications.OauthApplication
  alias ExOauth2Provider.OauthAccessTokens

  @valid_attrs    %{name: "Application", redirect_uri: "https://example.org/endpoint"}
  @invalid_attrs  %{}

  setup do
    {:ok, %{user: fixture(:user)}}
  end

  test "list_applications_for/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    {:ok, _} = OauthApplications.create_application(fixture(:user), @valid_attrs)
    assert [app] = OauthApplications.list_applications_for(user)
    assert app.id == application.id
  end

  test "get_application!/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    assert %OauthApplication{id: id} = OauthApplications.get_application!(application.uid)
    assert application.id == id
  end

  test "get_application/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    assert %OauthApplication{id: id} = OauthApplications.get_application(application.uid)
    assert application.id == id
  end

  test "get_application_for!/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    assert %OauthApplication{id: id} = OauthApplications.get_application_for!(user, application.uid)
    assert application.id == id

    assert_raise Ecto.NoResultsError, fn ->
      OauthApplications.get_application_for!(fixture(:user), application.uid)
    end
  end

  test "get_authorized_applications_for/1", %{user: user} do
    application = fixture(:application, fixture(:user), %{})
    application2 = fixture(:application, fixture(:user), %{uid: "newapp"})
    {:ok, token} = OauthAccessTokens.create_token(user, %{application: application})
    OauthAccessTokens.create_token(user, %{application: application2})
    assert [application, application2] == OauthApplications.get_authorized_applications_for(user)

    assert [] == OauthApplications.get_authorized_applications_for(fixture(:user))

    OauthAccessTokens.revoke(token)
    assert [application2] == OauthApplications.get_authorized_applications_for(user)
  end

  test "create_application/2 with valid attributes", %{user: user} do
    assert {:ok, %OauthApplication{} = application} = OauthApplications.create_application(user, @valid_attrs)
    assert application.name == @valid_attrs.name
  end

  test "create_application/2 with invalid attributes", %{user: user} do
    assert {:error, %Ecto.Changeset{}} = OauthApplications.create_application(user, @invalid_attrs)
  end

  test "create_application/2 adds random secret", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    {:ok, application2} = OauthApplications.create_application(user, @valid_attrs)
    assert application.secret != application2.secret
  end

  test "create_application/2 adds random uid", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    {:ok, application2} = OauthApplications.create_application(user, @valid_attrs)
    assert application.uid != application2.uid
  end

  test "create_application/2 adds custom uid", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, Map.merge(@valid_attrs, %{uid: "custom"}))
    assert application.uid == "custom"
  end

  test "create_application/2 adds custom secret", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, Map.merge(@valid_attrs, %{secret: "custom"}))
    assert application.secret == "custom"
  end

  test "update_application/2", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    assert {:ok, application} = OauthApplications.update_application(application, %{name: "Updated App"})
    assert application.name == "Updated App"
  end

  test "delete_application/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    assert {:ok, _} = OauthApplications.delete_application(application)
    assert_raise Ecto.NoResultsError, fn ->
      OauthApplications.get_application!(application.uid)
    end
  end

  test "change_application/1 validates name" do
    application = %OauthApplication{name: ""}
    changeset = OauthApplications.change_application(application)
    assert changeset.errors[:name]
  end

  test "change_application/1 validates uid" do
    application = %OauthApplication{uid: ""}
    changeset = OauthApplications.change_application(application)
    assert changeset.errors[:uid]
  end

  test "change_application/1 validates secret" do
    application = %OauthApplication{secret: ""}
    changeset = OauthApplications.change_application(application)
    assert changeset.errors[:secret]
  end

  test "change_application/1 requires redirect uri" do
    application = %OauthApplication{redirect_uri: ""}
    changeset = OauthApplications.change_application(application)
    assert changeset.errors[:redirect_uri]
  end

  test "change_application/1 doesn't require scopes" do
    application = %OauthApplication{scopes: ""}
    changeset = OauthApplications.change_application(application)
    refute changeset.errors[:scopes]
  end

  test "revoke_all_access_tokens_for/2", %{user: user} do
    application = fixture(:application, fixture(:user), %{})
    {:ok, token} = OauthAccessTokens.create_token(user, %{application: application})
    {:ok, token2} = OauthAccessTokens.create_token(user, %{application: application})
    {:ok, token3} = OauthAccessTokens.create_token(user, %{application: application})
    OauthAccessTokens.revoke(token3)

    assert {:ok, objects} = OauthApplications.revoke_all_access_tokens_for(application, user)
    assert 2 == Enum.count(objects)

    assert OauthAccessTokens.is_revoked?(ExOauth2Provider.repo.get!(OauthAccessTokens.OauthAccessToken, token.id))
    assert OauthAccessTokens.is_revoked?(ExOauth2Provider.repo.get!(OauthAccessTokens.OauthAccessToken, token2.id))
  end
end
