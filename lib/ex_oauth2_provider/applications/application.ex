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

  @callback changeset(ExOauth2Provider.Applications.Application.t(), map(), keyword()) ::
              Changeset.t()
  @optional_callbacks changeset: 3

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

      import unquote(__MODULE__), only: [application_fields: 0, application_fields: 1]

      defp except_fields(config), do: Config.application_except_fields(config)

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
        cast_fields = [:uid, :secret] -- except_fields(config)

        application
        |> Changeset.cast(params, cast_fields)
        |> put_uid()
        |> (fn changeset ->
              if :secret in except_fields(config) do
                changeset
              else
                put_secret(changeset)
              end
            end).()
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
        cast_fields = [:name, :secret, :redirect_uri, :scopes] -- except_fields(config)
        required_fields = [:name, :uid, :redirect_uri] -- except_fields(config)

        application
        |> maybe_new_application_changeset(params, config)
        |> Changeset.cast(params, cast_fields)
        |> Changeset.validate_required(required_fields)
        |> (fn changeset ->
              if :secret in except_fields(config) do
                changeset
              else
                validate_secret_not_nil(changeset)
              end
            end).()
        |> Scopes.validate_scopes(nil, config)
        |> (fn changeset ->
              if :redirect_uri in except_fields(config) do
                changeset
              else
                validate_redirect_uri(changeset, config)
              end
            end).()
        |> Changeset.unique_constraint(:uid)
      end

      defoverridable changeset: 3
    end
  end

  defmacro application_fields(opts \\ []) do
    except = ExOauth2Provider.Config.application_except_fields(opts)

    quote do
      ExOauth2Provider.Schema.fields(unquote(__MODULE__), except: unquote(except))
    end
  end
end
