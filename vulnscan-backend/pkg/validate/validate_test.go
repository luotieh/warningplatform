package validate

import "testing"

func TestIPv4List(t *testing.T) {
	if err := IPv4List("192.168.1.1,10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := IPv4List(""); err != nil {
		t.Fatal(err)
	}
	if err := IPv4List("999.1.1.1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestPort(t *testing.T) {
	if err := Port(0); err != nil {
		t.Fatal(err)
	}
	if err := Port(80); err != nil {
		t.Fatal(err)
	}
	if err := Port(70000); err == nil {
		t.Fatal("expected error")
	}
}

func TestCNPhone(t *testing.T) {
	for _, ok := range []string{"13800138000", "010-88886666", "+8613900138000"} {
		if err := CNPhone(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	if err := CNPhone("12345"); err == nil {
		t.Fatal("expected error")
	}
}

func TestUSCC(t *testing.T) {
	body := "91110000MA0000000"
	check := usccCharset[usccCheckIndex(body)]
	if err := USCC(body + string(check)); err != nil {
		t.Fatalf("valid uscc: %v", err)
	}
	if err := USCC("91110000"); err == nil {
		t.Fatal("expected length error")
	}
	if err := USCC(body + "0"); err == nil {
		t.Fatal("expected check digit error")
	}
}
