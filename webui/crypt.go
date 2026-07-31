// Package webui carries the Netgear web-UI ("HTTP") protocol layer: the
// per-model endpoint specs (endpoints.go) and the pure login crypto
// (crypt.go). Named webui, not http, to avoid stuttering against the
// stdlib net/http package this library's transport layer builds on.
//
// Ported field-for-field from
// src/netgear_switch/protocols/http/{endpoints,crypt}.py at pin 1841111 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1841111). Any discrepancy between this package and that pin
// is a bug in this package, not a deliberate deviation, unless called out
// in a comment.
package webui

import (
	"crypto/md5" //nolint:gosec // not a security use: replicating a firmware's own weak login hash, not protecting anything ourselves.
	"encoding/hex"
)

// Merge interleaves two strings character by character (Unicode code
// point, not byte), mirroring Python protocols.http.crypt.merge exactly:
// once the shorter string is exhausted, the remaining characters of the
// longer one are appended in order. This is the Netgear Plus-family login
// obfuscation scheme (GROUNDED against rcfiles/bin/netgear-smp-vlan and
// py_netgear_plus/netgear_crypt.py) -- not a security primitive.
func Merge(str1, str2 string) string {
	r1 := []rune(str1)
	r2 := []rune(str2)
	out := make([]rune, 0, len(r1)+len(r2))
	i, j := 0, 0
	for i < len(r1) || j < len(r2) {
		if i < len(r1) {
			out = append(out, r1[i])
			i++
		}
		if j < len(r2) {
			out = append(out, r2[j])
			j++
		}
	}
	return string(out)
}

// MergeHashMD5 returns md5(Merge(password, rand)) as lowercase hex, mirroring
// Python protocols.http.crypt.merge_hash_md5 (the Plus/GS110EMX login hash:
// see LoginSchemeMergeHashCGI / LoginSchemeGambit).
func MergeHashMD5(password, rand string) string {
	sum := md5.Sum([]byte(Merge(password, rand))) //nolint:gosec // see import comment above.
	return hex.EncodeToString(sum[:])
}
