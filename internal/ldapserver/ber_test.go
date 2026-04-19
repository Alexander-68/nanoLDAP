package ldapserver

import (
	"bytes"
	"testing"
)

func TestReadLengthRejectsOversizedPacket(t *testing.T) {
	// SEQUENCE tag (0x30) followed by long-form length 0xffffffff — a crafted
	// header that would otherwise cause a ~4 GiB allocation.
	data := []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}
	if _, err := readPacket(bytes.NewReader(data)); err == nil {
		t.Fatal("readPacket() accepted oversized length; want error")
	}
}

func TestReadLengthAcceptsWithinLimit(t *testing.T) {
	// Empty SEQUENCE is valid.
	if _, err := readPacket(bytes.NewReader([]byte{0x30, 0x00})); err != nil {
		t.Fatalf("readPacket() valid empty sequence error = %v", err)
	}
}
