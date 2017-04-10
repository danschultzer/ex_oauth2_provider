defmodule ExOauth2Provider.Utils do
  @moduledoc false

  @doc false
  def remove_empty_values(map) when is_map(map) do
    map
    |> Enum.filter(fn {_, v} -> v != nil && v != "" end)
    |> Enum.into(%{})
  end

  @doc false
  def generate_token(opts \\ %{}) do
    token_size = Map.get(opts, :size, 32)
    string = :crypto.strong_rand_bytes(token_size)
    Base.encode16(string, case: :lower)
  end
end
