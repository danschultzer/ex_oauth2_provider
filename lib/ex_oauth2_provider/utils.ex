defmodule ExOauth2Provider.Utils do
  @moduledoc false

  @doc false
  @spec remove_empty_values(map()) :: map()
  def remove_empty_values(map) when is_map(map) do
    map
    |> Enum.filter(fn {_, v} -> v != nil && v != "" end)
    |> Enum.into(%{})
  end

  @doc false
  @spec generate_token(keyword()) :: binary()
  def generate_token(opts \\ []) do
    opts
    |> Keyword.get(:size, 32)
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end
end
