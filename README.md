# ExOauth2Provider

The no brainer library to add OAuth 2 provider functionality to your elixir or phoenix app.

## Installation

Add ExOauth2Provider to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    # ...
    {:ex_oauth2_provider, "~> 0.1.0"}
    # ...
  ]
end
```

Run `mix deps.get` to install it. Add the following to `config/config.exs`:

```elixir
config :ex_oauth2_provider, ExOauth2Provider,
  repo: MyApp.Repo,
  resource_owner_model: MyApp.User
```

You should use a resource owner model that already exists in your app, like your user model. If you don't have nay user model, you can add a migration like this:

```bash
mix ecto.gen.migration --change "    create table(:users) do\n      add :email, :string\n    end"
```

And use the model in [test/support/dummy/models/user.ex](test/support/dummy/models/user.ex).

3. Add migrations

```bash
mix ex_oath2_provider.install
```

This will add all necessary migrations to your app.

## Usage

TBA

## Acknowledgement

This library was made thanks to [doorkeeper](https://github.com/doorkeeper-gem/doorkeeper), [guardian](https://github.com/ueberauth/guardian) and [authable](https://github.com/mustafaturan/authable), that gave the conceptual building blocks.

Thanks to [Benjamin Schultzer](https://github.com/schultzer) for helping refactoring the code.

## LICENSE

(The MIT License)

Copyright (c) 2017 Dan Schultzer & the Contributors Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
0
