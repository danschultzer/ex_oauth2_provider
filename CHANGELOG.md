# Changelog

## v0.5.7 (2023-08-05)

Requires Elixir 1.12+.

* Permit native application redirect uri
* Separate Ecto migration and field options to resolve ecto 3.8 deprecation

## v0.5.6 (2020-01-07)

* Permit associations to be overridden
* Updated the documentation for how to set application resource owner

## v0.5.5 (2019-10-31)

* Fixed bug where `Mix.env` is called on runtime rather than compile time

## v0.5.4 (2019-08-05)

* Improved error message for missing repo configuration
* A server issue at hex.pm caused v0.5.3 to not be released correctly. Use v0.5.4 instead.

## v0.5.3 (2019-08-02)

* Fixed bug in `ExOauth2Provider.RedirectURI.valid_for_authorization?/3` where the `:redirect_uri_match_fun` configuration option was not used
* Deprecated `ExOauth2Provider.RedirectURI.matches?/2`

## v0.5.2 (2019-06-10)

* Added `:redirect_uri_match_fun` configuration option for custom matching of redirect uri

## v0.5.1 (2019-05-08)

* Relaxed plug requirement up to 2.0.0
* Fix bug where otp app name could not be fetched in release

## v0.5.0 (2019-05-08)

This is a full rewrite of the library, and are several breaking changes. You're encouraged to test your app well if you upgrade from 0.4.

### Upgrading from 0.5

#### 1. DB

Add the string fields `code_challenge` and `code_challenge_method` to the table `<scope>_access_grants`.
Example migration file:

```elixir
# file: accounts/priv/repo/migrations/20210821193238_update_oauth_tables.exs
defmodule Accounts.Repo.Migrations.UpdateOauthTables do
  use Ecto.Migration

  def change do
    alter table(:oauth_access_grants) do
      add :code_challenge, :string
      add :code_challenge_method, :string
    end
  end
end

```

### Upgrading from 0.4

#### 1. Schema modules

Schema modules are now generated when installing ExOauth2Provider. To upgrade please run `mix ex_oauth2_provider.install --no-migrations` to generate the schema files.

In the `MyApp.OauthAccessGrants.OauthAccessGrant` schema module you should update the `timestamp/0` macro to ignore `:updated_at`:

```elixir
  schema "oauth_access_grants" do
    access_grant_fields()

    timestamps(updated_at: false)
  end
```

#### 2. Configuration

Config now has the form `config :my_app, ExOauth2Provider`. You can still use the previous `config :ex_oauth2_provider, ExOauth2Provider` configuration, but you are encouraged to switch over to the app specific configuration.

#### 3. Resource owner UUID configuration

If your configuration has `:resource_owner` setting with a UUID, you should remove it and only use the module name for your user schema. UUID is now handled in the schema modules directly.

The schemas can be generated with `mix ex_oauth2_provider.install --no-migrations --binary-id`.