defmodule ExOauth2Provider.OauthApplicationsTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.{OauthAccessTokens, OauthApplications, OauthApplications.OauthApplication}

  @valid_attrs    %{name: "Application", redirect_uri: "https://example.org/endpoint"}
  @invalid_attrs  %{}

  setup do
    {:ok, %{user: Fixtures.resource_owner()}}
  end

  test "get_applications_for/1", %{user: user} do
    assert {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    assert {:ok, _application} = OauthApplications.create_application(Fixtures.resource_owner(), @valid_attrs)

    assert [%OauthApplication{id: id}] = OauthApplications.get_applications_for(user)
    assert id == application.id
  end

  test "get_application!/1", %{user: user} do
    assert {:ok, application} = OauthApplications.create_application(user, @valid_attrs)

    assert %OauthApplication{id: id} = OauthApplications.get_application!(application.uid)
    assert id == application.id
  end

  test "get_application/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)

    assert %OauthApplication{id: id} = OauthApplications.get_application(application.uid)
    assert id == application.id
  end

  test "get_application_for!/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)

    assert %OauthApplication{id: id} = OauthApplications.get_application_for!(user, application.uid)
    assert id == application.id

    assert_raise Ecto.NoResultsError, fn ->
      OauthApplications.get_application_for!(Fixtures.resource_owner(), application.uid)
    end
  end

  test "get_authorized_applications_for/1", %{user: user} do
    application = Fixtures.application(Fixtures.resource_owner(), %{})
    application2 = Fixtures.application(Fixtures.resource_owner(), %{uid: "newapp"})
    assert {:ok, token} = OauthAccessTokens.create_token(user, %{application: application})
    assert {:ok, _token} = OauthAccessTokens.create_token(user, %{application: application2})

    assert OauthApplications.get_authorized_applications_for(user) == [application, application2]
    assert OauthApplications.get_authorized_applications_for(Fixtures.resource_owner()) == []

    OauthAccessTokens.revoke(token)
    assert OauthApplications.get_authorized_applications_for(user) == [application2]
  end

  test "create_application/2 with valid attributes", %{user: user} do
    assert {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    assert application.name == @valid_attrs.name
    assert application.scopes == "public"
  end

  test "create_application/2 with invalid attributes", %{user: user} do
    assert {:error, %Ecto.Changeset{}} = OauthApplications.create_application(user, @invalid_attrs)
  end

  test "create_application/2 with invalid scopes", %{user: user} do
    attrs = Map.merge(@valid_attrs, %{scopes: "invalid"})

    assert {:error, %Ecto.Changeset{}} = OauthApplications.create_application(user, attrs)
  end

  test "create_token/2 with limited scopes", %{user: user} do
    attrs = Map.merge(@valid_attrs, %{scopes: "read write"})

    assert {:ok, application} = OauthApplications.create_application(user, attrs)
    assert application.scopes == "read write"
  end

  test "create_application/2 adds random secret", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    {:ok, application2} = OauthApplications.create_application(user, @valid_attrs)

    assert application.secret != application2.secret
  end

  test "create_application/2 permits empty string secret", %{user: user} do
    attrs = Map.merge(@valid_attrs, %{secret: ""})

    assert {:ok, application} = OauthApplications.create_application(user, attrs)
    assert application.secret == ""
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
    assert {:ok, application} = OauthApplications.create_application(user, @valid_attrs)

    assert {:ok, application} = OauthApplications.update_application(application, %{name: "Updated App"})
    assert application.name == "Updated App"
  end

  test "delete_application/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)

    assert {:ok, _appliction} = OauthApplications.delete_application(application)
    assert_raise Ecto.NoResultsError, fn ->
      OauthApplications.get_application!(application.uid)
    end
  end

  test "change_application/1 validates name" do
    changeset = OauthApplications.change_application(%OauthApplication{name: ""})
    assert changeset.errors[:name]
  end

  test "change_application/1 validates uid" do
    changeset = OauthApplications.change_application(%OauthApplication{uid: ""})
    assert changeset.errors[:uid]
  end

  test "change_application/1 validates secret" do
    changeset = OauthApplications.change_application(%OauthApplication{secret: nil})
    assert changeset.errors[:secret] == {"can't be blank", []}

    changeset = OauthApplications.change_application(%OauthApplication{secret: ""})
    assert is_nil(changeset.errors[:secret])
  end

  test "change_application/1 requires valid redirect uri" do
    changeset = OauthApplications.change_application(%OauthApplication{redirect_uri: ""})
    assert changeset.errors[:redirect_uri]
  end

  test "create_application/2 require valid redirect uri" do
    ["",
     "invalid",
     "https://example.com invalid",
     "https://example.com http://example.com"]
    |> Enum.each(fn(redirect_uri) ->
      changeset = OauthApplications.change_application(%OauthApplication{redirect_uri: redirect_uri})
      assert changeset.errors[:redirect_uri]
    end)
  end

  test "change_application/1 doesn't require scopes" do
    changeset = OauthApplications.change_application(%OauthApplication{scopes: ""})
    refute changeset.errors[:scopes]
  end

  test "revoke_all_access_tokens_for/2", %{user: user} do
    application = Fixtures.application(Fixtures.resource_owner(), %{})
    {:ok, token} = OauthAccessTokens.create_token(user, %{application: application})
    {:ok, token2} = OauthAccessTokens.create_token(user, %{application: application})
    {:ok, token3} = OauthAccessTokens.create_token(user, %{application: application})
    OauthAccessTokens.revoke(token3)

    assert {:ok, objects} = OauthApplications.revoke_all_access_tokens_for(application, user)
    assert Enum.count(objects) == 2

    assert OauthAccessTokens.is_revoked?(ExOauth2Provider.repo.get!(OauthAccessTokens.OauthAccessToken, token.id))
    assert OauthAccessTokens.is_revoked?(ExOauth2Provider.repo.get!(OauthAccessTokens.OauthAccessToken, token2.id))
  end
end
