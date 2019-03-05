defmodule ExOauth2Provider.OauthApplications.OauthApplicationTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.OauthApplications.OauthApplication

  describe "changeset/2 with existing application" do
    setup do
      application = Ecto.put_meta(%OauthApplication{}, state: :loaded)

      {:ok, application: application}
    end

    test "validates", %{application: application} do
      changeset = OauthApplication.changeset(application, %{name: ""})
      assert changeset.errors[:name]
    end

    test "validates uid", %{application: application} do
      changeset = OauthApplication.changeset(application, %{uid: ""})
      assert changeset.errors[:uid]
    end

    test "validates secret", %{application: application} do
      changeset = OauthApplication.changeset(application, %{secret: nil})
      assert changeset.errors[:secret] == {"can't be blank", []}

      changeset = OauthApplication.changeset(application, %{secret: ""})
      assert is_nil(changeset.errors[:secret])
    end

    test "requires valid redirect uri", %{application: application} do
      changeset = OauthApplication.changeset(application, %{redirect_uri: ""})
      assert changeset.errors[:redirect_uri]
    end

    test "require valid redirect uri", %{application: application} do
      ["",
      "invalid",
      "https://example.com invalid",
      "https://example.com http://example.com"]
      |> Enum.each(fn(redirect_uri) ->
        changeset = OauthApplication.changeset(application, %{redirect_uri: redirect_uri})
        assert changeset.errors[:redirect_uri]
      end)
    end

    test "doesn't require scopes", %{application: application} do
      changeset = OauthApplication.changeset(application, %{scopes: ""})
      refute changeset.errors[:scopes]
    end
  end
end
