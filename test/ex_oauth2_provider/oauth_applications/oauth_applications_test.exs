defmodule ExOauth2Provider.OauthApplicationsTest do
  use ExOauth2Provider.TestCase
  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthApplications.OauthApplication

  @valid_attrs    %{name: "Application", redirect_uri: "https://example.org/endpoint"}
  @invalid_attrs  %{}

  setup do
    {:ok, %{user: ExOauth2Provider.Factory.insert(:user)}}
  end

  test "list_applications/0", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, @valid_attrs)
    assert [app] = OauthApplications.list_applications()
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
end
