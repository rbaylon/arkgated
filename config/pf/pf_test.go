package pfconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pfconfigmodel "github.com/rbaylon/srvcman/modules/pfconfig/model"
	pflowmodel "github.com/rbaylon/srvcman/modules/pflows/model"
)

// rundir returns a temp dir with the trailing separator ConfigCreate expects,
// since it concatenates rather than joins.
func rundir(t *testing.T) string {
	t.Helper()
	return t.TempDir() + string(os.PathSeparator)
}

func hostnameFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "hostname.") || e.Name() == "hostname." {
			out = append(out, e.Name())
		}
	}
	return out
}

// pflow exports are optional: with no records nothing at all is written.
func TestConfigCreateWritesNoPflowFileWhenThereAreNoRecords(t *testing.T) {
	dir := rundir(t)
	for _, c := range []*pfconfigmodel.Pfconfig{
		{},                             // nil Pflows
		{Pflows: []pflowmodel.Pflow{}}, // empty slice
	} {
		if err := ConfigCreate(c, dir); err != nil {
			t.Fatalf("ConfigCreate: %v", err)
		}
		if files := hostnameFiles(t, dir); len(files) != 0 {
			t.Errorf("no pflow records should write no hostname files, got %v", files)
		}
	}
}

func TestConfigCreateWritesCompletePflowExport(t *testing.T) {
	dir := rundir(t)
	c := &pfconfigmodel.Pfconfig{Pflows: []pflowmodel.Pflow{
		{Device: "pflow0", Src: "127.0.0.1", Dst: "10.0.0.5:9995", Proto: 10},
	}}
	if err := ConfigCreate(c, dir); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "hostname.pflow0"))
	if err != nil {
		t.Fatalf("hostname.pflow0 not written: %v", err)
	}
	got := string(b)
	for _, want := range []string{"flowsrc 127.0.0.1", "flowdst 10.0.0.5:9995", "pflowproto 10"} {
		if !strings.Contains(got, want) {
			t.Errorf("hostname.pflow0 missing %q; got:\n%s", want, got)
		}
	}
}

// An incomplete export must be skipped rather than rendered - a missing device
// would create a file literally named "hostname.", and a missing src/dst/proto
// would create a malformed one that breaks netstart for that interface.
func TestConfigCreateSkipsIncompletePflowExports(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  pflowmodel.Pflow
	}{
		{"no device", pflowmodel.Pflow{Src: "127.0.0.1", Dst: "10.0.0.5:9995", Proto: 10}},
		{"no src", pflowmodel.Pflow{Device: "pflow0", Dst: "10.0.0.5:9995", Proto: 10}},
		{"no dst", pflowmodel.Pflow{Device: "pflow0", Src: "127.0.0.1", Proto: 10}},
		{"no proto", pflowmodel.Pflow{Device: "pflow0", Src: "127.0.0.1", Dst: "10.0.0.5:9995"}},
		{"bad proto", pflowmodel.Pflow{Device: "pflow0", Src: "127.0.0.1", Dst: "10.0.0.5:9995", Proto: 9}},
		{"device only", pflowmodel.Pflow{Device: "pflow0"}},
	} {
		dir := rundir(t)
		c := &pfconfigmodel.Pfconfig{Pflows: []pflowmodel.Pflow{tc.row}}
		if err := ConfigCreate(c, dir); err != nil {
			t.Fatalf("%s: ConfigCreate should not fail, got %v", tc.name, err)
		}
		if files := hostnameFiles(t, dir); len(files) != 0 {
			t.Errorf("%s: incomplete export should write nothing, got %v", tc.name, files)
		}
	}
}

// The file named "hostname." is the specific accident worth naming: netstart
// would be handed an interface with no name.
func TestConfigCreateNeverWritesBareHostnameFile(t *testing.T) {
	dir := rundir(t)
	c := &pfconfigmodel.Pfconfig{Pflows: []pflowmodel.Pflow{
		{Device: "", Src: "127.0.0.1", Dst: "10.0.0.5:9995", Proto: 10},
	}}
	if err := ConfigCreate(c, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hostname.")); !os.IsNotExist(err) {
		t.Errorf(`a file named "hostname." was created (err=%v)`, err)
	}
}

// A complete export alongside an incomplete one still gets written: one bad row
// must not suppress the others.
func TestConfigCreateSkipsOnlyTheIncompletePflowRow(t *testing.T) {
	dir := rundir(t)
	c := &pfconfigmodel.Pfconfig{Pflows: []pflowmodel.Pflow{
		{Device: "pflow0"}, // incomplete
		{Device: "pflow1", Src: "127.0.0.1", Dst: "10.0.0.5:9995", Proto: 5},
	}}
	if err := ConfigCreate(c, dir); err != nil {
		t.Fatal(err)
	}
	files := hostnameFiles(t, dir)
	if len(files) != 1 || files[0] != "hostname.pflow1" {
		t.Errorf("want only hostname.pflow1, got %v", files)
	}
}
