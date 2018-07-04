defmodule ExOauth2Provider.Keys do
  @moduledoc false

  @doc false
  @spec access_token_key(atom()) :: atom()
  def access_token_key(key \\ :default) do
    String.to_atom("#{base_key(key)}_access_token")
  end

  @doc false
  @spec base_key(binary()) :: atom()
  def base_key("ex_oauth2_provider_" <> _ = the_key) do
    String.to_atom(the_key)
  end

  @doc false
  @spec base_key(atom()) :: atom()
  def base_key(the_key) do
    String.to_atom("ex_oauth2_provider_#{the_key}")
  end
end
