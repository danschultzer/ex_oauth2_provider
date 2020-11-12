defmodule ExOauth2Provider.Changeset do
  @moduledoc """
  This module defines behaviour for oauth changesets
  """
  @callback allowed_fields() :: nonempty_list(atom())
  @callback required_fields() :: nonempty_list(atom())
  @callback request_fields() :: nonempty_list(binary())

  defmacro __using__(_) do
    quote do
      @behaviour ExOauth2Provider.Changeset
    end
  end
end
