package ldapserver

import (
	"bytes"
	"testing"
)

func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add(bindRequest(1, "", ""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readPacket(bytes.NewReader(data))
	})
}
