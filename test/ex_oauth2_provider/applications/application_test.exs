defmodule ExOauth2Provider.Applications.ApplicationTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Applications.Application
  alias Dummy.OauthApplications.OauthApplication

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
      ["", "invalid", "https://example.com invalid", "https://example.com http://example.com"]
      |> Enum.each(fn redirect_uri ->
        changeset = OauthApplication.changeset(application, %{redirect_uri: redirect_uri})
        assert changeset.errors[:redirect_uri]
      end)
    end

    test "doesn't require scopes", %{application: application} do
      changeset = OauthApplication.changeset(application, %{scopes: ""})
      refute changeset.errors[:scopes]
    end
  end

  defmodule OverrideOwner do
    @moduledoc false

    use Ecto.Schema
    use ExOauth2Provider.Applications.Application, otp_app: :ex_oauth2_provider

    if System.get_env("UUID") do
      @primary_key {:id, :binary_id, autogenerate: true}
      @foreign_key_type :binary_id
    end

    schema "oauth_applications" do
      belongs_to(:owner, __MODULE__)

      application_fields()
      timestamps()
    end
  end

  test "with overridden `:owner`" do
    assert %Ecto.Association.BelongsTo{owner: OverrideOwner} =
             OverrideOwner.__schema__(:association, :owner)
  end

  defmodule AddExtraField do
    @moduledoc false

    use Ecto.Schema

    use ExOauth2Provider.Applications.Application,
      otp_app: :ex_oauth2_provider

    if System.get_env("UUID") do
      @primary_key {:id, :binary_id, autogenerate: true}
      @foreign_key_type :binary_id
    end

    schema "oauth_applications" do
      field(:description, :string)
      field(:reference, Ecto.UUID)

      application_fields()
      timestamps()
    end

    def changeset(application, params, config \\ []) do
      super(application, params, config)
      |> Ecto.Changeset.cast(params, [:reference, :description])
    end
  end

  describe "changeset/2 with extra fields" do
    test "validates" do
      changeset =
        AddExtraField.changeset(%AddExtraField{}, %{
          name: "test",
          scopes: "public",
          redirect_uri: "https://example.org/endpoint",
          uid: ExOauth2Provider.Utils.generate_token(),
          reference: Ecto.UUID.generate(),
          description: "lorem ipsum"
        })

      assert changeset.valid?
      assert {:ok, _uuid} = Ecto.UUID.dump(changeset.changes.reference)
      assert changeset.changes.description == "lorem ipsum"
    end
  end
end
