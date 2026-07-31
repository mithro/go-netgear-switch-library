package webui_test

import (
	"crypto/md5" //nolint:gosec // test asserts against the same weak reference hash the firmware uses.
	"encoding/hex"
	"testing"

	"github.com/mithro/go-netgear-switch-library/webui"
)

// TestMergeInterleavesCharacters pins webui.Merge against
// protocols/http/crypt.py::merge (dossier §4 / tests/protocols/http/
// test_crypt.py::test_merge_interleaves_characters), including the two
// unequal-length cases where the longer string's remainder is appended
// verbatim once the shorter string is exhausted.
func TestMergeInterleavesCharacters(t *testing.T) {
	cases := []struct {
		name   string
		s1, s2 string
		want   string
	}{
		{"equal length odd", "abc", "12", "a1b2c"},
		{"s1 longer", "ab", "1234", "a1b234"},
		{"s1 empty", "", "xy", "xy"},
		{"s2 empty", "xy", "", "xy"},
		{"both empty", "", "", ""},
		{"single chars", "a", "1", "a1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := webui.Merge(c.s1, c.s2); got != c.want {
				t.Errorf("Merge(%q, %q) = %q, want %q", c.s1, c.s2, got, c.want)
			}
		})
	}
}

// TestMergeUnicode exercises Merge on multi-byte runes to confirm the
// interleave operates on Unicode code points (matching Python str
// indexing), not raw UTF-8 bytes -- a plain byte-indexed port would split a
// multi-byte rune in half.
func TestMergeUnicode(t *testing.T) {
	got := webui.Merge("aé", "1€")
	want := "a1é€"
	if got != want {
		t.Errorf("Merge(%q, %q) = %q, want %q", "aé", "1€", got, want)
	}
}

// TestMergeHashMD5MatchesReference pins webui.MergeHashMD5 against
// hashlib.md5(merge(...)).hexdigest() (test_crypt.py::
// test_merge_hash_md5_matches_reference).
func TestMergeHashMD5MatchesReference(t *testing.T) {
	sum := md5.Sum([]byte(webui.Merge("s3cr3t", "9917"))) //nolint:gosec
	want := hex.EncodeToString(sum[:])
	if got := webui.MergeHashMD5("s3cr3t", "9917"); got != want {
		t.Errorf("MergeHashMD5(%q, %q) = %q, want %q", "s3cr3t", "9917", got, want)
	}
	if got := len(webui.MergeHashMD5("p", "r")); got != 32 {
		t.Errorf("len(MergeHashMD5(%q, %q)) = %d, want 32", "p", "r", got)
	}
}

// TestMergeHashMD5WithGS110EMXCapturedRand exercises MergeHashMD5 against
// "1172334327", the real `rand` nonce captured live from a physical
// GS110EMX's login page (test_crypt.py::
// test_merge_hash_md5_with_gs110emx_captured_rand). The real admin password
// used during that capture was never recorded, so -- as in the Python
// original -- this only proves the function runs correctly against the real
// nonce; it cannot assert a specific expected hash without the real
// password.
func TestMergeHashMD5WithGS110EMXCapturedRand(t *testing.T) {
	const rand = "1172334327"
	sum := md5.Sum([]byte(webui.Merge("some-password", rand))) //nolint:gosec
	want := hex.EncodeToString(sum[:])
	got := webui.MergeHashMD5("some-password", rand)
	if got != want {
		t.Errorf("MergeHashMD5(%q, %q) = %q, want %q", "some-password", rand, got, want)
	}
	if len(got) != 32 {
		t.Errorf("len(MergeHashMD5(%q, %q)) = %d, want 32", "some-password", rand, len(got))
	}
}

// TestMergeHashMD5IsLowercaseHex confirms the 32-char output is entirely
// lowercase hex (hex.EncodeToString's contract, but pinned explicitly since
// the Python reference calls this out as a documented property of
// merge_hash_md5).
func TestMergeHashMD5IsLowercaseHex(t *testing.T) {
	got := webui.MergeHashMD5("hunter2", "42")
	for _, r := range got {
		isLowerHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isLowerHex {
			t.Fatalf("MergeHashMD5 output %q contains non-lowercase-hex rune %q", got, r)
		}
	}
}
