defmodule ExOauth2Provider.Utils.Validation do
  @moduledoc false

  # see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
  @code_verifier_regex ~r/^[[:alnum:]._~-]{43,128}$/

  @spec valid_code_verifier_format?(String.t()) :: boolean
  def valid_code_verifier_format?(nil), do: false
  def valid_code_verifier_format?(code_verifier), do: String.match?(code_verifier, @code_verifier_regex)
end
