package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStdinDomainsArg(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "separate dash becomes joined",
			in:   []string{"--domains", "-", "--json"},
			want: []string{"--domains=-", "--json"},
		},
		{
			name: "already joined is left alone",
			in:   []string{"--domains=-", "--quiet"},
			want: []string{"--domains=-", "--quiet"},
		},
		{
			name: "file path is left alone",
			in:   []string{"--domains", "hosts.txt"},
			want: []string{"--domains", "hosts.txt"},
		},
		{
			name: "domains without a value is left alone",
			in:   []string{"--domains"},
			want: []string{"--domains"},
		},
		{
			name: "empty",
			in:   nil,
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stdinDomainsArg(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("stdinDomainsArg(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestGetDomainListFilePath(t *testing.T) {
	got, err := getDomainListFilePath("-")
	if err != nil || got != "-" {
		t.Fatalf("stdin path: got %q, %v", got, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = getDomainListFilePath(path)
	if err != nil || got != path {
		t.Fatalf("existing file: got %q, %v", got, err)
	}

	missing := filepath.Join(dir, "missing.txt")
	if _, err := getDomainListFilePath(missing); err == nil {
		t.Fatal("expected an error for a missing domains file")
	}
}
