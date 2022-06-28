defmodule ExOauth2Provider.Utils.DeviceFlowTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Utils.DeviceFlow

  describe "#generate_device_code/1" do
    test "returns a unique 32 char string that's base64 encoded and url safe" do
      expected_length =
        "01234567890123456789012345678912"
        |> Base.url_encode64()
        |> String.length()

      codes = Enum.map(1..10, fn _n -> DeviceFlow.generate_device_code() end)

      num_uniq_codes =
        codes
        |> Enum.uniq()
        |> Enum.count()

      assert num_uniq_codes == 10

      assert Enum.all?(
               codes,
               fn code ->
                 assert code =~ ~r/[a-z0-9=_-]{#{expected_length}}/i
               end
             )
    end

    test "uses the length in the config when defined" do
      code =
        DeviceFlow.generate_device_code(
          otp_app: :ex_oauth2_provider,
          device_flow_device_code_length: 10
        )

      expected_length =
        "0123456789"
        |> Base.url_encode64()
        |> String.length()

      assert String.length(code) == expected_length
    end
  end

  describe "#generate_user_code/1" do
    test "returns a unique 8 char alpha-numeric string" do
      codes = Enum.map(1..10, fn _n -> DeviceFlow.generate_user_code() end)

      num_uniq_codes =
        codes
        |> Enum.uniq()
        |> Enum.count()

      assert num_uniq_codes == 10

      assert Enum.all?(
               codes,
               fn code ->
                 assert code =~ ~r/[a-z0-9]{8}/i
               end
             )
    end

    test "returns a code the same length as device_flow_device_code_length when given" do
      code =
        DeviceFlow.generate_user_code(
          otp_app: :ex_oauth2_provider,
          device_flow_user_code_length: 4
        )

      assert String.length(code) == 4
    end

    test "returns a code using the value of device_flow_user_code_base when given" do
      code =
        DeviceFlow.generate_user_code(
          otp_app: :ex_oauth2_provider,
          device_flow_user_code_base: 2
        )

      assert code =~ ~r/[01]{8}/
    end
  end
end
