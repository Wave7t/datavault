package auth

import (
	"reflect"
	"testing"
)

func TestParseProcStatusGroups(t *testing.T) {
	sample := []byte("Name:\tdvault\nUmask:\t0022\nState:\tR\n" +
		"Uid:\t1020\t1020\t1020\t1020\nGid:\t1020\t1020\t1020\t1020\n" +
		"Groups:\t1020 1050 1099 \nNStgid:\t0\n")
	gids, err := ParseProcStatusGroups(sample)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{1020, 1050, 1099}
	if !reflect.DeepEqual(gids, want) {
		t.Fatalf("got %v want %v", gids, want)
	}
}

func TestParseProcStatusGroups_MissingLine(t *testing.T) {
	_, err := ParseProcStatusGroups([]byte("Name:\tdvault\n"))
	if err == nil {
		t.Fatal("expected error when Groups: line absent")
	}
}

func TestParseProcStatusGroups_EmptyLine(t *testing.T) {
	gids, err := ParseProcStatusGroups([]byte("Groups:\t\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(gids) != 0 {
		t.Fatalf("expected empty, got %v", gids)
	}
}

func TestParseProcStatusGroups_MalformedGID(t *testing.T) {
	_, err := ParseProcStatusGroups([]byte("Groups:\t1020 notanumber\n"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}
