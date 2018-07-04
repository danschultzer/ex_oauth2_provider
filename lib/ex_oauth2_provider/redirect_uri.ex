defmodule ExOauth2Provider.RedirectURI do
  @moduledoc """
  Functions for dealing with redirect uri.
  """
  alias ExOauth2Provider.Utils
  alias ExOauth2Provider.Config

  @doc """
  Validates if a url can be used as a redirect_uri
  """
  @spec validate(binary() | nil) :: {:ok, binary()} | {:errror, binary()}
  def validate(nil), do: validate("")
  def validate(url) do
    case String.trim(url) do
      "" ->
        {:error, "Redirect URI cannot be blank"}

      url ->
        uri = URI.parse(url)

        cond do
          native_redirect_uri?(url) ->
            {:ok, url}

          uri.fragment != nil ->
            {:error, "Redirect URI cannot contain fragments"}

          uri.scheme == nil || uri.host == nil ->
            {:error, "Redirect URI must be an absolute URI"}

          invalid_ssl_uri?(uri) ->
            {:error, "Redirect URI must be an HTTPS/SSL URI"}

          true ->
            {:ok, url}
        end
    end
  end

  @doc """
  Check if uri matches client uri
  """
  @spec matches?(binary(), binary()) :: boolean()
  def matches?(uri, client_uri) when is_binary(uri) and is_binary(client_uri) do
    matches?(URI.parse(uri), URI.parse(client_uri))
  end
  @spec matches?(URI.t(), URI.t()) :: boolean()
  def matches?(%URI{} = uri, %URI{} = client_uri) do
    uri = Map.merge(uri, %{query: nil})

    client_uri == uri
  end

  @doc """
  Check if a url matches a client redirect_uri
  """
  @spec valid_for_authorization?(binary(), binary()) :: boolean()
  def valid_for_authorization?(url, client_url) do
    case validate(url) do
      {:error, _} ->
        false

      {:ok, _} ->
        client_url
        |> String.split()
        |> Enum.any?(&matches?(url, &1))
    end
  end

  @doc """
  Check if a url is native
  """
  @spec native_redirect_uri?(binary()) :: boolean()
  def native_redirect_uri?(url) do
    Config.native_redirect_uri == url
  end

  @doc """
  Adds query parameters to uri
  """
  @spec uri_with_query(binary() | URI.t(), binary()) :: URI.t()
  def uri_with_query(uri, query) when is_binary(uri),
    do: uri_with_query(URI.parse(uri), query)
  def uri_with_query(%URI{} = uri, query) do
    uri
    |> Map.merge(%{query: add_query_params(uri.query, query)})
    |> to_string()
  end

  defp add_query_params(query, attrs) do
    (query || "")
    |> URI.decode_query(attrs)
    |> Utils.remove_empty_values()
    |> URI.encode_query()
  end

  defp invalid_ssl_uri?(uri) do
    Config.force_ssl_in_redirect_uri?() and uri.scheme == "http"
  end
end
