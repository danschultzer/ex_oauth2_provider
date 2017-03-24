defmodule ExOauth2Provider.Scopes do
  @moduledoc """
  Functions for dealing with scopes.
  """

  @doc """
  Check if required scopes exists in the scopes list
  """
  def all?(scopes, required_scopes) do
    required_scopes
    |> Enum.find(fn(item) -> !Enum.member?(scopes, item) end)
    |> is_nil
  end

  @doc """
  Check if two strings or lists of scopes are equal
  """
  def equal?(scopes, other_scopes) when is_binary(scopes) do
    equal?(to_list(scopes), other_scopes)
  end
  def equal?(scopes, other_scopes) when is_binary(other_scopes) do
    equal?(scopes, to_list(other_scopes))
  end
  def equal?(scopes, other_scopes) do
    all?(scopes, other_scopes) && all?(other_scopes, scopes)
  end

  # Fetch scopes from access token
  @spec from_access_token(map) :: list
  def from_access_token(access_token) do
    access_token.scopes
    |> to_list
  end

  # Convert scopes string to list
  @spec to_list(string) :: list
  def to_list(str), do: trim_split(str, ",")
  defp trim_split(str, char) do
    str
    |> String.replace(~r/([\s]+)/, "")
    |> String.split(char, trim: true)
  end

  # Convert scopes list to string
  @spec to_string(list) :: string
  def to_string(scopes), do: Enum.join(scopes, ",")
end
