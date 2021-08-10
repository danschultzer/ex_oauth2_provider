defmodule ExOauth2Provider.Oidc do
  @moduledoc """
    Functions to add an OIDC layer to this OAuth implementation
  """

  alias ExOauth2Provider.Config
  # alias ExOauth2Provider.Oidc.Token

  def generate_token(resource_owner, %{uid: client_id}, config) do
    oidc_config = Config.oidc(config)

    audience = Keyword.get(oidc_config, :audience, client_id)
    issuer = Keyword.get(oidc_config, :issuer, "https://retailpay.africa")
    resource_owner_claims = Keyword.get(oidc_config, :resource_owner_claims, [:id])

    signer = Joken.Signer.create("HS256", "secret")

    config =
      %{}
      |> Joken.Config.add_claim("iss", fn -> issuer end, &(&1 == issuer))
      |> Joken.Config.add_claim("aud", fn -> audience end, &(&1 == audience))

    extra_claims = recursive_take(resource_owner, resource_owner_claims)
    Joken.generate_and_sign!(config, extra_claims, signer)
  end

  defp recursive_take(map, fields) do
    take = fn
      maps, fields when is_list(maps) -> Enum.map(maps, &recursive_take(&1, fields))
      map, fields when is_map(map) -> recursive_take(map, fields)
    end

    {plain, nested} =
      Enum.reduce(fields, {[], []}, fn field, {plain, nested} ->
        if is_tuple(field), do: {plain, nested ++ [field]}, else: {plain ++ [field], nested}
      end)

    initial_map = Map.take(map, plain)

    Enum.reduce(nested, initial_map, fn {key, fields}, accum ->
      value =
        map
        |> Map.fetch!(key)
        |> take.(fields)

      Map.put(accum, key, value)
    end)
  end
end
