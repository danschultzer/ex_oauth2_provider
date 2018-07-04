defmodule ExOauth2Provider.Test.FileHelpers do
  @moduledoc false

  import ExUnit.Assertions

  @doc """
  Returns the `tmp_path` for tests.
  """
  def tmp_path do
    Path.expand("../../tmp", __DIR__)
  end

  @doc """
  Asserts a file was generated.
  """
  def assert_file(file) do
    assert File.regular?(file), "Expected #{file} to exist, but does not"
  end

  @doc """
  Asserts a file was generated and that it matches a given pattern.
  """
  def assert_file(file, callback) when is_function(callback, 1) do
    assert_file(file)
    callback.(File.read!(file))
  end
end
