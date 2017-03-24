defmodule ExOauth2Provider.Utils do
  @moduledoc """
  Utility functions
  """

  def remove_empty_values(map) when is_map(map) do
    map
    |> Enum.filter(fn {_, v} -> v != nil && v != "" end)
    |> Enum.into(%{})
  end
end
