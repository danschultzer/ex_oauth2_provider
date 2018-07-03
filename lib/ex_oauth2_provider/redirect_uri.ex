defmodule ExOauth2Provider.RedirectURI do
  @moduledoc """
  Functions for dealing with redirect uri.
  """
  import ExOauth2Provider.Utils

  @doc """
  Validates if a url can be used as a redirect_uri
  """
  @spec validate(String.t | nil) :: {:ok, String.t} | {:errror, String.t}
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
  @spec matches?(String.t, String.t) :: boolean
  @spec matches?(%URI{}, %URI{}) :: boolean
  def matches?(uri, client_uri) when is_binary(uri) and is_binary(client_uri) do
    matches?(URI.parse(uri), URI.parse(client_uri))
  end
  def matches?(%URI{} = uri, %URI{} = client_uri) do
    uri = Map.merge(uri, %{query: nil})

    client_uri == uri
  end

  @doc """
  Check if a url matches a client redirect_uri
  """
  @spec valid_for_authorization?(String.t, String.t) :: boolean
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
  @spec native_redirect_uri?(String.t) :: boolean
  def native_redirect_uri?(url) do
    ExOauth2Provider.Config.native_redirect_uri == url
  end

  @doc """
  Adds query parameters to uri
  """
  @spec uri_with_query(String.t | URI.t, String.t) :: URI.t
  def uri_with_query(uri, query) when is_binary(uri),
    do: uri_with_query(URI.parse(uri), query)
  def uri_with_query(%URI{} = uri, query) do
    uri
    |> Map.merge(%{query: add_query_params(uri.query, query)})
    |> put_query_to_fragment()
    |> to_string()
  end

  defp add_query_params(query, attrs) do
    (query || "")
    |> URI.decode_query(attrs)
    |> remove_empty_values()
    |> URI.encode_query()
  end

  defp put_query_to_fragment(uri) do
    if uri.query |> URI.decode_query() |> Map.has_key?("access_token") do
      %{uri | query: nil, fragment: uri.query}
    else
      uri
    end
  end

  defp invalid_ssl_uri?(uri) do
    ExOauth2Provider.Config.force_ssl_in_redirect_uri?() and uri.scheme == "http"
  end
end
