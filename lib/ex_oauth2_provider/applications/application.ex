defmodule ExOauth2Provider.Applications.Application do
  @moduledoc """
  Handles the Ecto schema for application.

  ## Usage

  Configure `lib/my_project/oauth_applications/oauth_application.ex` the following way:

      defmodule MyApp.OauthApplications.OauthApplication do
        use Ecto.Schema
        use ExOauth2Provider.Applications.Application

        schema "oauth_applications" do
          application_fields()

          timestamps()
        end

        # Optionally, you can implement the changeset callback which is called after
        # the default changeset.
        @impl ExOauth2Provider.Applications.Application
        def changeset(changeset) do
          # ...
        end
      end

  ## Application owner

  By default the application owner will be will be the `:resource_owner`
  configuration setting. You can override this by overriding the `:owner`
  belongs to association:

      defmodule MyApp.OauthApplications.OauthApplication do
        use Ecto.Schema
        use ExOauth2Provider.Applications.Application

        schema "oauth_applications" do
          belongs_to :owner, MyApp.Users.User

          application_fields()

          timestamps()
        end
      end
  """
  alias Ecto.Changeset
  alias ExOauth2Provider.{Config, RedirectURI, Utils}
  alias ExOauth2Provider.Mixin.Scopes

  @type t :: Ecto.Schema.t()

  @callback changeset(ExOauth2Provider.Applications.Application.t(), map()) ::
              Changeset.t()
  @optional_callbacks changeset: 2

  @doc false
  def attrs() do
    [
      {:name, :string, null: false},
      {:uid, :string, null: false},
      {:secret, :string, null: false, default: ""},
      {:redirect_uri, :string, null: false},
      {:scopes, :string, null: false, default: ""}
    ]
  end

  @doc false
  def assocs() do
    [
      {:belongs_to, :owner, :users},
      {:has_many, :access_tokens, :access_tokens, foreign_key: :application_id}
    ]
  end

  @doc false
  def indexes(), do: [{:uid, true}]

  @doc false
  defmacro __using__(config) do
    quote do
      @behaviour ExOauth2Provider.Applications.Application

      use ExOauth2Provider.Schema, unquote(config)

      # For Phoenix integrations
      if Code.ensure_loaded?(Phoenix.Param), do: @derive({Phoenix.Param, key: :uid})

      import unquote(__MODULE__), only: [application_fields: 0]

      @impl ExOauth2Provider.Applications.Application
      def changeset(application_changeset, _params), do: application_changeset

      defoverridable changeset: 2
    end
  end

  defmacro application_fields() do
    quote do
      ExOauth2Provider.Schema.fields(unquote(__MODULE__))
    end
  end

  defp validate_secret_not_nil(changeset) do
    case Changeset.get_field(changeset, :secret) do
      nil -> Changeset.add_error(changeset, :secret, "can't be blank")
      _ -> changeset
    end
  end

  defp maybe_new_application_changeset(application, params, config) do
    case Ecto.get_meta(application, :state) do
      :built -> new_application_changeset(application, params, config)
      :loaded -> application
    end
  end

  defp new_application_changeset(application, params, config) do
    application
    |> Changeset.cast(params, [:uid, :secret])
    |> put_uid()
    |> put_secret()
    |> Scopes.put_scopes(nil, config)
    |> Changeset.assoc_constraint(:owner)
  end

  defp validate_redirect_uri(changeset, config) do
    changeset
    |> Changeset.get_field(:redirect_uri)
    |> Kernel.||("")
    |> String.split()
    |> Enum.reduce(changeset, fn url, changeset ->
      url
      |> RedirectURI.validate(config)
      |> case do
        {:error, error} -> Changeset.add_error(changeset, :redirect_uri, error)
        {:ok, _} -> changeset
      end
    end)
  end

  defp put_uid(%{changes: %{uid: _}} = changeset), do: changeset

  defp put_uid(%{} = changeset) do
    Changeset.change(changeset, %{uid: Utils.generate_token()})
  end

  defp put_secret(%{changes: %{secret: _}} = changeset), do: changeset

  defp put_secret(%{} = changeset) do
    Changeset.change(changeset, %{secret: Utils.generate_token()})
  end

  @spec changeset(Ecto.Schema.t(), map(), keyword()) :: Changeset.t()
  def changeset(application, params, config \\ []) do
    application
    |> maybe_new_application_changeset(params, config)
    |> Changeset.cast(params, [:name, :secret, :redirect_uri, :scopes])
    |> Changeset.validate_required([:name, :uid, :redirect_uri])
    |> validate_secret_not_nil()
    |> Scopes.validate_scopes(nil, config)
    |> validate_redirect_uri(config)
    |> Changeset.unique_constraint(:uid)
    |> Config.application(config).changeset(params)
  end
end
