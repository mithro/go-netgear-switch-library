package webui

// client_internal_test.go: white-box coverage for client.go's unexported
// xmlAPIQuote -- not reachable from package webui_test's black-box tests,
// which only see loginXMLAPI's already-assembled URL and can't distinguish
// its wire form from an equivalent one (e.g. Go's net/url query parser
// decodes both "%20" and "+" back to a space, so a black-box round trip
// can't catch xmlAPIQuote regressing to url.QueryEscape's '+'/'%2F' output
// -- see xmlAPIQuote's own doc comment, and [HTTP-QUOTE]).

import (
	"strings"
	"testing"
)

// TestXMLAPIQuoteMatchesPythonQuoteDefaultSafeSlash pins xmlAPIQuote's
// output against Python's urllib.parse.quote(s) (default safe='/'), the
// pin's own encoder for this login URL (client.py:150-154, pin b26eb1f) --
// VERIFIED against a live CPython 3 interpreter:
//
//	>>> from urllib.parse import quote
//	>>> quote("pa ss/wo rd")
//	'pa%20ss/wo%20rd'
//	>>> quote("a+b c/d")
//	'a%2Bb%20c/d'
//	>>> quote("admin")
//	'admin'
func TestXMLAPIQuoteMatchesPythonQuoteDefaultSafeSlash(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"space and slash", "pa ss/wo rd", "pa%20ss/wo%20rd"},
		{"plus, space, and slash", "a+b c/d", "a%2Bb%20c/d"},
		{"already-safe username", "admin", "admin"},
		{"unreserved punctuation passes through", "a_b-c.d~e", "a_b-c.d~e"},
		{"leading/trailing/doubled slash preserved literally", "/a//b/", "/a//b/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := xmlAPIQuote(c.in); got != c.want {
				t.Errorf("xmlAPIQuote(%q) = %q, want %q (Python urllib.parse.quote parity)", c.in, got, c.want)
			}
		})
	}
}

// TestXMLAPIQuoteDiffersFromNetURLEscapers pins the exact reason neither of
// net/url's exported escapers is a substitute -- see xmlAPIQuote's own doc
// comment -- so a future "just use the stdlib helper" simplification is
// caught here instead of only live against a GS728TPP.
func TestXMLAPIQuoteDiffersFromNetURLEscapers(t *testing.T) {
	const password = "pa ss/wo rd"
	got := xmlAPIQuote(password)
	if want := "pa%20ss/wo%20rd"; got != want {
		t.Fatalf("xmlAPIQuote(%q) = %q, want %q", password, got, want)
	}
	if !strings.Contains(got, "/") {
		t.Errorf("xmlAPIQuote(%q) = %q, want a literal '/' preserved (url.PathEscape would encode it %%2F)", password, got)
	}
	if strings.Contains(got, "+") {
		t.Errorf("xmlAPIQuote(%q) = %q, want no '+' for space (url.QueryEscape would use '+', not %%20)", password, got)
	}
}
