defmodule ExOauth2Provider.RedirectURI do
  @moduledoc """
  Functions for dealing with redirect uri.
  """
  alias ExOauth2Provider.{Config, Utils}

  @doc """
  Validates if a url can be used as a redirect_uri.

  Validates according to [RFC 6749 3.1.2](https://tools.ietf.org/html/rfc6749#section-3.1.2)
  and [RFC 8252 7.1](https://tools.ietf.org/html/rfc8252#section-7.1). The validation is
  skipped if the redirect uri is the same as the `:native_redirect_uri` configuration
  setting.
  """
  @spec validate(binary() | nil, keyword()) :: {:ok, binary()} | {:error, binary()}
  def validate(nil, config), do: validate("", config)
  def validate(url, config) when is_binary(url) do
    url
    |> String.trim()
    |> case do
      "" ->
        {:error, "Redirect URI cannot be blank"}

      url ->
        case native_redirect_uri?(url, config) do
          true  -> {:ok, url}
          false -> do_validate(url, URI.parse(url), config)
        end
    end
  end

  defp do_validate(_url, %{fragment: fragment}, _config) when not is_nil(fragment),
    do: {:error, "Redirect URI cannot contain fragments"}
  defp do_validate(url, %{scheme: scheme} = uri, config) when not is_nil(scheme) do
    case invalid_ssl_uri?(uri, config) do
      true  -> {:error, "Redirect URI must be an HTTPS/SSL URI"}
      false -> {:ok, url}
    end
  end
  defp do_validate(_url, _uri, _config),
    do: {:error, "Redirect URI must be an absolute URI"}

  defp invalid_ssl_uri?(%{scheme: "http"}, config), do: Config.force_ssl_in_redirect_uri?(config)
  defp invalid_ssl_uri?(_uri, _config), do: false

  @doc false
  @deprecated "Use `matches?/3` instead"
  def matches?(uri, client_uri), do: matches?(uri, client_uri, [])

  @doc """
  Check if uri matches client uri
  """
  @spec matches?(binary(), binary(), keyword()) :: boolean()
  def matches?(uri, client_uri, config) when is_binary(uri) and is_binary(client_uri) do
    matches?(URI.parse(uri), URI.parse(client_uri), config)
  end
  @spec matches?(URI.t(), URI.t(), keyword()) :: boolean()
  def matches?(%URI{} = uri, %URI{} = client_uri, config) do
    case Config.redirect_uri_match_fun(config) do
      nil -> client_uri == %{uri | query: nil}
      fun -> fun.(uri, client_uri, config)
    end
  end

  @doc """
  Check if a url matches a client redirect_uri
  """
  @spec valid_for_authorization?(binary(), binary(), keyword()) :: boolean()
  def valid_for_authorization?(url, client_url, config) do
    url
    |> validate(config)
    |> do_valid_for_authorization?(client_url, config)
  end

  defp do_valid_for_authorization?({:error, _error}, _client_url, _config), do: false
  defp do_valid_for_authorization?({:ok, url}, client_url, config) do
    client_url
    |> String.split()
    |> Enum.any?(&matches?(url, &1, config))
  end

  @doc """
  Check if a url is native
  """
  @spec native_redirect_uri?(binary(), keyword()) :: boolean()
  def native_redirect_uri?(url, config) do
    Config.native_redirect_uri(config) == url
  end

  @doc """
  Adds query parameters to uri
  """
  @spec uri_with_query(binary() | URI.t(), map()) :: binary()
  def uri_with_query(uri, query) when is_binary(uri) do
    uri
    |> URI.parse()
    |> uri_with_query(query)
  end
  def uri_with_query(%URI{} = uri, query) do
    query = add_query_params(uri.query || "", query)

    uri
    |> Map.put(:query, query)
    |> to_string()
  end

  defp add_query_params(query, attrs) do
    query
    |> URI.decode_query(attrs)
    |> Utils.remove_empty_values()
    |> URI.encode_query()
  end
end
