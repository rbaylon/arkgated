package webconf

import (
	"os"
	"strings"
	"testing"
)

// The fixture is verbatim `ifconfig -a` from an OpenBSD 7.9 box, so the parser
// is tested against real output rather than output I invented.
func loadFixture(t *testing.T) []HostIface {
	t.Helper()
	b, err := os.ReadFile("testdata/ifconfig-openbsd79.txt")
	if err != nil {
		t.Fatal(err)
	}
	return parseIfconfig(strings.NewReader(string(b)))
}

func find(t *testing.T, ifs []HostIface, dev string) HostIface {
	t.Helper()
	for _, h := range ifs {
		if h.Device == dev {
			return h
		}
	}
	t.Fatalf("interface %s not parsed; got %d interfaces", dev, len(ifs))
	return HostIface{}
}

func TestParseRealOpenBSDIfconfig(t *testing.T) {
	ifs := loadFixture(t)

	var names []string
	for _, h := range ifs {
		names = append(names, h.Device)
	}
	want := "lo0 em0 em1 enc0 pflog0"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("parsed %q, want %q", got, want)
	}

	// em0 is the live NIC holding the default route.
	em0 := find(t, ifs, "em0")
	if !em0.Up() {
		t.Error("em0 should be up")
	}
	if !em0.Egress() {
		t.Error("em0 is in the egress group and should report it")
	}
	if em0.MAC != "08:00:27:34:c2:e7" {
		t.Errorf("em0 MAC = %q", em0.MAC)
	}
	if em0.Media != "1000baseT full-duplex" {
		t.Errorf("em0 media = %q", em0.Media)
	}
	if em0.SpeedHint() != "1000M" {
		t.Errorf("em0 speed hint = %q, want 1000M", em0.SpeedHint())
	}
	if em0.Status != "active" {
		t.Errorf("em0 status = %q", em0.Status)
	}
	// ifconfig prints the mask in hex; everything downstream wants dotted.
	if em0.IP != "10.0.2.15" || em0.Netmask != "255.255.255.0" {
		t.Errorf("em0 addr = %q/%q, want 10.0.2.15/255.255.255.0", em0.IP, em0.Netmask)
	}

	// em1 is a real NIC but administratively down and unaddressed - still a
	// perfectly good thing to assign in the config.
	em1 := find(t, ifs, "em1")
	if em1.Up() {
		t.Error("em1 should not be up")
	}
	if em1.Egress() {
		t.Error("em1 is not in the egress group")
	}
	if em1.IP != "" {
		t.Errorf("em1 should have no address, got %q", em1.IP)
	}
	if !em1.Assignable() {
		t.Error("em1 is a physical NIC and must be assignable even while down")
	}
}

func TestOnlyPhysicalNICsAreAssignable(t *testing.T) {
	ifs := loadFixture(t)

	var assignable []string
	for _, h := range ifs {
		if h.Assignable() {
			assignable = append(assignable, h.Device)
		}
	}
	if got := strings.Join(assignable, " "); got != "em0 em1" {
		t.Errorf("assignable = %q, want %q", got, "em0 em1")
	}

	// The pseudo-devices must be excluded, and for the documented reason:
	// no lladdr and no media line.
	for _, dev := range []string{"lo0", "enc0", "pflog0"} {
		h := find(t, ifs, dev)
		if h.Assignable() {
			t.Errorf("%s should not be assignable", dev)
		}
		if h.MAC != "" || h.Media != "" {
			t.Errorf("%s: expected no lladdr/media, got %q/%q", dev, h.MAC, h.Media)
		}
	}
}

func TestArkgatedManagedDevicesNeverOffered(t *testing.T) {
	// These are created by arkgated from this very config, so offering one as
	// a parent device would be circular. They are filtered by name because a
	// vlan does carry an lladdr and media line inherited from its parent.
	for _, dev := range []string{"vlan0", "vlan100", "svlan3", "pppac0", "pppx1", "pflow0", "pflog0", "enc0", "lo0", "carp1", "bridge0", "veb0", "tpmr0"} {
		if !arkgatedManaged(dev) {
			t.Errorf("%s should be treated as arkgated-managed", dev)
		}
		h := HostIface{Device: dev, MAC: "08:00:27:00:00:01", Media: "1000baseT full-duplex"}
		if h.Assignable() {
			t.Errorf("%s must not be assignable even with lladdr+media", dev)
		}
	}

	// Real NIC drivers must survive the filter, including ones whose names
	// merely begin with a filtered prefix.
	for _, dev := range []string{"em0", "igc0", "ix1", "ixl0", "bnxt0", "re0", "urtwn0", "vmx0", "lom0", "encx0", "vlanfoo"} {
		if arkgatedManaged(dev) {
			t.Errorf("%s is a real driver name and must not be filtered", dev)
		}
	}
}

func TestMediaRate(t *testing.T) {
	for _, tc := range []struct{ media, want string }{
		{"1000baseT full-duplex", "1000M"},
		{"100baseTX full-duplex", "100M"},
		{"10baseT", "10M"},
		{"2500baseT full-duplex", "2500M"},
		{"10GbaseSR", "10G"},
		{"autoselect", ""},
		{"none", ""},
		{"", ""},
	} {
		if got := mediaRate(tc.media); got != tc.want {
			t.Errorf("mediaRate(%q) = %q, want %q", tc.media, got, tc.want)
		}
	}
}

func TestHexMaskToDotted(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0xffffff00", "255.255.255.0"},
		{"0xffff0000", "255.255.0.0"},
		{"0xff000000", "255.0.0.0"},
		{"0xfffffffc", "255.255.255.252"},
		{"garbage", ""},
	} {
		if got := hexMaskToDotted(tc.in); got != tc.want {
			t.Errorf("hexMaskToDotted(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
