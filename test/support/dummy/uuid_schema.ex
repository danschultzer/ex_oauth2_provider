defmodule Dummy.UUIDSchema do
  @moduledoc false
  defmacro __using__(_) do
    quote do
      use Ecto.Schema
      unless is_nil(System.get_env("UUID")) do
        @primary_key {:id, :binary_id, autogenerate: true}
        @foreign_key_type :binary_id
      end
    end
  end
end
