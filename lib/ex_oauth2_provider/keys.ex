defmodule ExOauth2Provider.Keys do
  @moduledoc false

  @doc false
  def resource_key(key \\ :default) do
    String.to_atom("#{base_key(key)}_resource")
  end

  @doc false
  def token_key(key \\ :default) do
    String.to_atom("#{base_key(key)}_token")
  end

  @doc false
  def base_key(the_key = "ex_oauth2_provider_" <> _) do
    String.to_atom(the_key)
  end

  @doc false
  def base_key(the_key) do
    String.to_atom("ex_oauth2_provider_#{the_key}")
  end
end
