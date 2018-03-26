defmodule ExOauth2Provider.Schema do
  @moduledoc """
  This module will permit dynamic App.Schema load.
  """
  defmacro __using__(_) do
    quote do
      use unquote(ExOauth2Provider.Config.app_schema())
    end
  end
end
