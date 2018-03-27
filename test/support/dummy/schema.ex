defmodule Dummy.Schema do
  @moduledoc """
  This module will permit dynamic App.Schema load.
  """
  defmacro __using__(_) do
    schema = if is_nil(System.get_env("UUID")),
      do: Ecto.Schema,
      else: ExOauth2Provider.Schema.UUID

    quote do
      use unquote(schema)
    end
  end
end
