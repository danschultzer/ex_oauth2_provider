defmodule ExOauth2Provider.RedirectURI do
  @moduledoc """
  Functions for dealing with redirect uri.
  """

  @doc """
  Validates whether a url can be used as a redirect_uri
  """
  def validate(nil), do: validate("")
  def validate(url) do
    case String.strip(url) do
      "" -> {:error, "Redirect URI cannot be blank"}
      url ->
        uri = URI.parse(url)
        cond do
          url == ExOauth2Provider.native_redirect_uri ->
            {:ok, url}
          uri.fragment != nil ->
            {:error, "Redirect URI cannot contain fragments"}
          uri.scheme == nil || uri.host == nil ->
            {:error, "Redirect URI has to be absolute"}
          true ->
            {:ok, url}
        end
    end
  end

  @doc """
  Check if uri matches client uri
  """
  def matches?(uri, client_uri) when is_binary(uri) do
    matches?(URI.parse(uri), client_uri)
  end
  def matches?(uri, client_uri) when is_binary(client_uri) do
    matches?(uri, URI.parse(client_uri))
  end
  def matches?(uri, client_uri) do
    uri = uri
    |> Map.merge(%{query: nil})
    client_uri == uri
  end

  @doc """
  Check if an url matches a client redirect_uri
  """
  def valid_for_authorization?(url, client_url) do
    case validate(url) do
      {:error, _} -> false
      {:ok, _} ->
        client_url
        |> String.split
        |> Enum.any?(fn(other_url) -> matches?(url, other_url) end)
    end
  end

  @doc """
  Check if an url is native
  """
  def native_uri?(url) do
    ExOauth2Provider.native_redirect_uri == url
  end
end
