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
  Check if two lists of scopes are equal
  """
  def equal?(scopes, other_scopes) do
    all?(scopes, other_scopes) && all?(other_scopes, scopes)
  end

  @doc """
  Default scopes for server
  """
  def default_server_scopes do
    ExOauth2Provider.Config.default_scopes
  end

  @doc """
  All scopes for server
  """
  def server_scopes do
    ExOauth2Provider.Config.server_scopes
  end

  @doc """
  Fetch scopes from an access token
  """
  @spec from_access_token(map) :: list
  def from_access_token(access_token) do
    access_token.scopes
    |> to_list
  end

  @doc """
  Convert scopes string to list
  """
  @spec to_list(String.t()) :: list
  def to_list(nil), do: []
  def to_list(str) do
    String.split(str)
  end

  @doc """
  Convert scopes list to string
  """
  @spec to_string(list) :: String.t()
  def to_string(scopes) do
    Enum.join(scopes, " ")
  end
end
