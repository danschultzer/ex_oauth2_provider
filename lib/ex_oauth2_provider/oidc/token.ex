defmodule ExOauth2Provider.Oidc.Token do
  @moduledoc false

  use Joken.Config

   def token_config do
    %{}
    |> add_claim("iss", fn -> "https://retailpay.africa" end, &(&1 == "https://retailpay.africa"))
  end
end
