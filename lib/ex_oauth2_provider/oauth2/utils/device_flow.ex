defmodule ExOauth2Provider.Utils.DeviceFlow do
  alias ExOauth2Provider.Config

  @spec generate_device_code() :: binary()
  @spec generate_device_code(keyword()) :: binary()
  def generate_device_code(config \\ [otp_app: :ex_oauth2_provider]) do
    config
    |> Config.device_flow_device_code_length()
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64()
  end

  @spec generate_user_code() :: binary()
  @spec generate_user_code(keyword()) :: binary()
  def generate_user_code(config \\ [otp_app: :ex_oauth2_provider]) do
    # NOTE: Integer.pow only exists in elixir 1.12+
    # So we have to convert erlangs pow response to integer
    # Thanks to Doorkeeper for this!
    max_length = Config.device_flow_user_code_length(config)
    base = Config.device_flow_user_code_base(config)

    base
    |> :math.pow(max_length)
    |> trunc()
    |> :rand.uniform()
    |> Integer.to_string(base)
    |> String.upcase()
    |> String.pad_leading(max_length, "0")
  end
end
