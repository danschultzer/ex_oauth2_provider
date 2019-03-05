defmodule ExOauth2Provider.Scopes do
  @moduledoc """
  Functions for dealing with scopes.
  """

  alias ExOauth2Provider.Config

  @doc """
  Check if required scopes exists in the scopes list
  """
  @spec all?([binary()], [binary()]) :: boolean()
  def all?(scopes, required_scopes) do
    (required_scopes -- scopes) == []
  end

  @doc """
  Check if two lists of scopes are equal
  """
  @spec equal?([binary()], [binary()]) :: boolean()
  def equal?(scopes, other_scopes) do
    Enum.sort(scopes) == Enum.sort(other_scopes)
  end

  @doc """
  Default scopes for server
  """
  @spec default_server_scopes() :: [binary()]
  def default_server_scopes, do: Config.default_scopes()

  @doc """
  All scopes for server
  """
  @spec server_scopes() :: [binary()]
  def server_scopes, do: Config.server_scopes()

  @doc """
  Filter defaults scopes from scopes list
  """
  @spec filter_default_scopes([binary()]) :: [binary()]
  def filter_default_scopes(scopes) do
    default_scopes = default_server_scopes()

    Enum.filter(scopes, &Enum.member?(default_scopes, &1))
  end

  @doc """
  Will default to server scopes if no scopes supplied
  """
  @spec default_to_server_scopes([binary()]) :: [binary()]
  def default_to_server_scopes([]), do: Config.server_scopes()
  def default_to_server_scopes(server_scopes), do: server_scopes

  @doc """
  Fetch scopes from an access token
  """
  @spec from_access_token(map()) :: [binary()]
  def from_access_token(access_token), do: to_list(access_token.scopes)

  @doc """
  Convert scopes string to list
  """
  @spec to_list(binary()) :: [binary()]
  def to_list(nil), do: []
  def to_list(str), do: String.split(str)

  @doc """
  Convert scopes list to string
  """
  @spec to_string(list()) :: binary()
  def to_string(scopes), do: Enum.join(scopes, " ")
end
