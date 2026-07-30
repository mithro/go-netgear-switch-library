package main

import (
	"strings"
	"testing"
)

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name        string
		profile     string
		wantTotal   int64
		wantCovered int64
		wantErr     bool
	}{
		{
			name: "exempt scripts and cmd paths skipped",
			profile: strings.Join([]string{
				"mode: set",
				"github.com/mithro/go-netgear-switch-library/model/types.go:33.2,33.10 1 1",
				"github.com/mithro/go-netgear-switch-library/scripts/coveragegate/main.go:10.1,12.2 5 0",
				"github.com/mithro/go-netgear-switch-library/cmd/foo/main.go:10.1,12.2 3 0",
			}, "\n"),
			wantTotal:   1,
			wantCovered: 1,
		},
		{
			name: "covered and uncovered statements counted",
			profile: strings.Join([]string{
				"mode: set",
				"github.com/mithro/go-netgear-switch-library/model/types.go:1.1,2.2 4 1",
				"github.com/mithro/go-netgear-switch-library/model/types.go:3.1,4.2 6 0",
			}, "\n"),
			wantTotal:   10,
			wantCovered: 4,
		},
		{
			name: "malformed line missing fields returns error",
			profile: strings.Join([]string{
				"mode: set",
				"github.com/mithro/go-netgear-switch-library/model/types.go:1.1,2.2 4",
			}, "\n"),
			wantErr: true,
		},
		{
			name: "malformed line non-numeric numStmt returns error",
			profile: strings.Join([]string{
				"mode: set",
				"github.com/mithro/go-netgear-switch-library/model/types.go:1.1,2.2 x 1",
			}, "\n"),
			wantErr: true,
		},
		{
			name: "malformed line missing colon returns error",
			profile: strings.Join([]string{
				"mode: set",
				"not a valid profile line at all",
			}, "\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			total, covered, err := parseProfile(strings.NewReader(tt.profile))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseProfile() err = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProfile() unexpected err = %v", err)
			}
			if total != tt.wantTotal {
				t.Errorf("total = %d, want %d", total, tt.wantTotal)
			}
			if covered != tt.wantCovered {
				t.Errorf("covered = %d, want %d", covered, tt.wantCovered)
			}
		})
	}
}

func TestExemptPath(t *testing.T) {
	tests := []struct {
		file string
		want bool
	}{
		{"github.com/mithro/go-netgear-switch-library/model/types.go", false},
		{"github.com/mithro/go-netgear-switch-library/scripts/coveragegate/main.go", true},
		{"github.com/mithro/go-netgear-switch-library/cmd/netgear-switch-cli/main.go", true},
		{"github.com/mithro/go-netgear-switch-library/config.go", false},
	}
	for _, tt := range tests {
		if got := exemptPath(tt.file); got != tt.want {
			t.Errorf("exemptPath(%q) = %v, want %v", tt.file, got, tt.want)
		}
	}
}
