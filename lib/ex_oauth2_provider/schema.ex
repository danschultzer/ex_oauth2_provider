defmodule ExOauth2Provider.Schema do
  @moduledoc """
  This module will permit dynamic App.Schema load.
  """

  alias ExOauth2Provider.Config

  defmacro __using__(_) do
    quote do
      use unquote(Config.app_schema())
    end
  end
end
