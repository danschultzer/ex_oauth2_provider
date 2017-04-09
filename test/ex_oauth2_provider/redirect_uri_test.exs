defmodule ExOauth2Provider.RedirectURITest do
  use ExUnit.Case
  import ExOauth2Provider.RedirectURI

  test "validate native url" do
    uri = ExOauth2Provider.native_redirect_uri
    assert validate(uri) == {:ok, uri}
  end

  test "validate rejects blank" do
    assert validate("") == {:error, "Redirect URI cannot be blank"}
    assert validate(nil) == {:error, "Redirect URI cannot be blank"}
    assert validate("  ") == {:error, "Redirect URI cannot be blank"}
  end

  test "validate rejects with fragment" do
    assert validate("https://app.co/test#fragment") == {:error, "Redirect URI cannot contain fragments"}
  end

  test "validate rejects with missing scheme" do
    assert validate("app.co") == {:error, "Redirect URI must be an absolute URI"}
  end

  test "validate rejects relative url" do
    assert validate("/abc/123") == {:error, "Redirect URI must be an absolute URI"}
  end

  test "validate rejects scheme only" do
    assert validate("https://") == {:error, "Redirect URI must be an absolute URI"}
  end

  test "validate https scheme" do
    assert validate("http://app.co/") == {:error, "Redirect URI must be an HTTPS/SSL URI"}
  end

  test "validate" do
    uri = "https://app.co"
    assert validate(uri) == {:ok, uri}
    uri = "https://app.co/path"
    assert validate(uri) == {:ok, uri}
    uri = "https://app.co/?query=1"
    assert validate(uri) == {:ok, uri}
  end

  test "matches?#true" do
    uri = "https://app.co/aaa"
    assert matches?(uri, uri)
  end

  test "matches?#true ignores query parameter on comparison" do
    assert matches?("https://app.co/?query=hello", "https://app.co/")
  end

  test "matches?#false" do
    refute matches?("https://app.co/?query=hello", "https://app.co")
  end

  test "matches?#false with domains that doesn't start at beginning" do
    refute matches?("https://app.co/?query=hello", "https://example.com?app.co=test")
  end

  test "valid_for_authorization?#true" do
    uri = "https://app.co/aaa"
    assert valid_for_authorization?(uri, uri)
  end

  test "valid_for_authorization?#false" do
    refute valid_for_authorization?("https://app.co/aaa", "https://app.co/bbb")
  end

  test "valid_for_authorization?#true with array" do
    assert valid_for_authorization?("https://app.co/aaa", "https://example.com/bbb\nhttps://app.co/aaa")
  end

  test "valid_for_authorization?#false with invalid uri" do
    uri = "https://app.co/aaa?waffles=abc"
    refute valid_for_authorization?(uri, uri)
  end

  test "uri_with_query/2" do
    assert uri_with_query("https://example.com/", %{parameter: "value"}) == "https://example.com/?parameter=value"
  end

  test "uri_with_query/2 rejects nil values" do
    assert uri_with_query("https://example.com/", %{parameter: nil}) == "https://example.com/?"
  end

  test "uri_with_query/2 preserves original query parameters" do
    uri = uri_with_query("https://example.com/?query1=value", %{parameter: "value"})
    assert Regex.match?(~r/query1=value/, uri)
    assert Regex.match?(~r/parameter=value/, uri)
  end
end
