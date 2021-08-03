use Mix.Config

config :phoenix, :json_library, Jason

if Mix.env() == :test do
  import_config "test.exs"
end
