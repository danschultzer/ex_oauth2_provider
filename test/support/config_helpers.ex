defmodule ExOauth2Provider.Test.ConfigHelpers do
  @moduledoc false

  @config Application.get_env(:ex_oauth2_provider, ExOauth2Provider)

  def reset_config do
    set_config(@config)
  end

  def set_config(config) do
    Application.put_env(:ex_oauth2_provider, ExOauth2Provider, config)
  end

  def set_config(key, value) do
    @config
    |> Keyword.put(key, value)
    |> set_config()
  end
end
