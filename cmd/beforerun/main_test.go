package main

import (
	"reflect"
	"testing"
)

func TestNormalizeArgsAllowsFlagsAfterPath(t *testing.T) {
	got := normalizeArgs([]string{".", "--fail-on", "medium", "--format=json"})
	want := []string{"--fail-on", "medium", "--format=json", "."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeArgs() = %#v, want %#v", got, want)
	}
}

func TestNormalizeArgsPreservesBooleanFlags(t *testing.T) {
	got := normalizeArgs([]string{"repo", "--quiet"})
	want := []string{"--quiet", "repo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeArgs() = %#v, want %#v", got, want)
	}
}
