defmodule ExOauth2Provider.Oidc do
  @moduledoc """
    Functions to add an OIDC layer to this OAuth implementation
  """

  alias ExOauth2Provider.Config
  # alias ExOauth2Provider.Oidc.Token

  def generate_token resource_owner, %{uid: client_id}, config do

    oidc_config = Config.oidc(config)

    audience = Keyword.get(oidc_config, :audience, client_id)
    issuer = Keyword.get(oidc_config, :issuer, "https://retailpay.africa")
    resource_owner_claims = Keyword.get(oidc_config, :resource_owner_claims, [:id])

    signer = Joken.Signer.create("HS256", "secret")

    config = %{}
    |> Joken.Config.add_claim("iss", fn -> issuer end, &(&1 == issuer))
    |> Joken.Config.add_claim("aud", fn -> audience end, & &1 == audience)

    extra_claims =  Map.take(resource_owner, resource_owner_claims)
    Joken.generate_and_sign!(config, extra_claims, signer)
  end
end
