defmodule ExOauth2Provider.RedirectURI do
  @moduledoc """
  Functions for dealing with redirect uri.
  """
  alias ExOauth2Provider.{Config, Utils}

  defmodule Behaviour do
    @moduledoc false
    @callback validate(binary() | nil, keyword()) :: {:ok, binary()} | {:error, binary()}
    @callback matches?(binary(), binary()) :: boolean()
    @callback matches?(URI.t(), URI.t()) :: boolean()
    @callback valid_for_authorization?(binary(), binary(), keyword()) :: boolean()
    @callback native_redirect_uri?(binary(), keyword()) :: boolean()
    @callback uri_with_query(binary() | URI.t(), map()) :: binary()
  end

  @behaviour Behaviour

  @doc """
  You can override the behaviour of RedirectURI by providing your own custom implementation.

  ## Examples

      defmodule MyApp.RedirectURI do
        use ExOauth2Provider.RedirectURI

        def validate(url, config) do
          # Custom implementatation
        end
      end

      # config.exs
      config :my_app, ExOauth2Provider,
        redirect_uri: MyApp.RedirectURI
  """
  defmacro __using__(_opts) do
    quote do
      @behaviour unquote(__MODULE__.Behaviour)

      defdelegate validate(url, config), to: unquote(__MODULE__)
      defdelegate matches?(url, url), to: unquote(__MODULE__)
      defdelegate valid_for_authorization?(url, client_url, config), to: unquote(__MODULE__)
      defdelegate native_redirect_uri?(url, config), to: unquote(__MODULE__)
      defdelegate uri_with_query(uri, query), to: unquote(__MODULE__)

      defoverridable unquote(__MODULE__)
    end
  end

  @doc """
  Validates if a url can be used as a redirect_uri
  """
  @impl true
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
  defp do_validate(_url, %{scheme: schema, host: host}, _config) when is_nil(schema) or is_nil(host),
    do: {:error, "Redirect URI must be an absolute URI"}
  defp do_validate(url, uri, config) do
    if invalid_ssl_uri?(uri, config) do
      {:error, "Redirect URI must be an HTTPS/SSL URI"}
    else
      {:ok, url}
    end
  end

  defp invalid_ssl_uri?(uri, config) do
    Config.force_ssl_in_redirect_uri?(config) and uri.scheme == "http"
  end

  @doc """
  Check if uri matches client uri
  """
  @impl true
  @spec matches?(binary(), binary()) :: boolean()
  def matches?(uri, client_uri) when is_binary(uri) and is_binary(client_uri) do
    matches?(URI.parse(uri), URI.parse(client_uri))
  end
  @spec matches?(URI.t(), URI.t()) :: boolean()
  def matches?(%URI{} = uri, %URI{} = client_uri) do
    client_uri == %{uri | query: nil}
  end

  @doc """
  Check if a url matches a client redirect_uri
  """
  @impl true
  @spec valid_for_authorization?(binary(), binary(), keyword()) :: boolean()
  def valid_for_authorization?(url, client_url, config) do
    url
    |> validate(config)
    |> do_valid_for_authorization?(client_url)
  end

  defp do_valid_for_authorization?({:error, _error}, _client_url), do: false
  defp do_valid_for_authorization?({:ok, url}, client_url) do
    client_url
    |> String.split()
    |> Enum.any?(&matches?(url, &1))
  end

  @doc """
  Check if a url is native
  """
  @impl true
  @spec native_redirect_uri?(binary(), keyword()) :: boolean()
  def native_redirect_uri?(url, config) do
    Config.native_redirect_uri(config) == url
  end

  @doc """
  Adds query parameters to uri
  """
  @impl true
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
