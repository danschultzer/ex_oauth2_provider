require Mix.ExOauth2Provider.Migration

binary_id = if System.get_env("UUID"), do: true, else: false

"CreateOauthTables"
|> Mix.ExOauth2Provider.Migration.gen("oauth", %{
  repo: ExOauth2Provider.Test.Repo,
  binary_id: binary_id,
  device_code: true
})
|> Code.eval_string()
