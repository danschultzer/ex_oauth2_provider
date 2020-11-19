defmodule ExOauth2Provider.Applications do
  @moduledoc """
  Defines a behaviour for interacting with an application.
  """

  alias Ecto.Schema
  alias ExOauth2Provider.{Applications.Application, Config}

  @callback get_application!(binary(), keyword()) :: Application.t() | no_return
  def get_application!(uid, config \\ []), do: strategy(config).get_application!(uid, config)

  @callback get_application_for!(Schema.t(), binary(), keyword()) :: Application.t() | no_return
  def get_application_for!(resource_owner, uid, config \\ []),
    do: strategy(config).get_application_for!(resource_owner, uid, config)

  @callback get_application(binary(), keyword()) :: Application.t() | nil
  def get_application(uid, config \\ []), do: strategy(config).get_application(uid, config)

  @callback load_application(binary(), binary(), keyword()) :: Application.t() | nil
  def load_application(uid, secret \\ "", config \\ []),
    do: strategy(config).load_application(uid, secret, config)

  @callback get_applications_for(Schema.t(), keyword()) :: [Application.t()]
  def get_applications_for(resource_owner, config \\ []),
    do: strategy(config).get_applications_for(resource_owner, config)

  @callback get_authorized_applications_for(Schema.t(), keyword()) :: [Application.t()]
  def get_authorized_applications_for(resource_owner, config \\ []),
    do: strategy(config).get_authorized_applications_for(resource_owner, config)

  @callback change_application(Application.t(), map(), keyword()) :: Changeset.t()
  def change_application(application, attrs \\ %{}, config \\ []),
    do: strategy(config).change_application(application, attrs, config)

  @callback create_application(Schema.t(), map(), keyword()) ::
              {:ok, Application.t()} | {:error, Changeset.t()}
  def create_application(owner, attrs \\ %{}, config \\ []),
    do: strategy(config).create_application(owner, attrs, config)

  @callback update_application(Application.t(), map(), keyword()) ::
              {:ok, Application.t()} | {:error, Changeset.t()}
  def update_application(application, attrs, config \\ []),
    do: strategy(config).update_application(application, attrs, config)

  @callback delete_application(Application.t(), keyword()) ::
              {:ok, Application.t()} | {:error, Changeset.t()}
  def delete_application(application, config \\ []),
    do: strategy(config).delete_application(application, config)

  @callback revoke_all_access_tokens_for(Application.t(), Schema.t(), keyword()) ::
              {:ok, [ok: AccessToken.t()]} | {:error, any()}
  def revoke_all_access_tokens_for(application, resource_owner, config \\ []),
    do: strategy(config).revoke_all_access_tokens_for(application, resource_owner, config)

  defp strategy(config), do: Config.application_strategy(config)
end
