package ldapserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	classUniversal   = 0
	classApplication = 1
	classContext     = 2
)

type packet struct {
	class       int
	tag         int
	constructed bool
	content     []byte
	children    []packet
}

func readPacket(r io.Reader) (packet, error) {
	var tagByte [1]byte
	if _, err := io.ReadFull(r, tagByte[:]); err != nil {
		return packet{}, err
	}
	length, err := readLength(r)
	if err != nil {
		return packet{}, err
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(r, content); err != nil {
		return packet{}, err
	}
	return decodePacket(tagByte[0], content)
}

func decodePacket(tagByte byte, content []byte) (packet, error) {
	pkt := packet{
		class:       int(tagByte >> 6),
		tag:         int(tagByte & 0x1f),
		constructed: tagByte&0x20 != 0,
		content:     content,
	}
	if pkt.tag == 0x1f {
		return packet{}, errors.New("high-tag-number form is not supported")
	}
	if !pkt.constructed {
		return pkt, nil
	}
	reader := bytes.NewReader(content)
	for reader.Len() > 0 {
		child, err := readPacket(reader)
		if err != nil {
			return packet{}, err
		}
		pkt.children = append(pkt.children, child)
	}
	return pkt, nil
}

func readLength(r io.Reader) (int, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	if first[0]&0x80 == 0 {
		return int(first[0]), nil
	}
	count := int(first[0] & 0x7f)
	if count == 0 {
		return 0, errors.New("indefinite lengths are not supported")
	}
	if count > 4 {
		return 0, errors.New("length is too large")
	}
	buf := make([]byte, count)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	length := 0
	for _, b := range buf {
		length = (length << 8) | int(b)
	}
	return length, nil
}

func (p packet) int() (int, error) {
	if len(p.content) == 0 {
		return 0, errors.New("empty integer")
	}
	value := int(int8(p.content[0]))
	for i := 1; i < len(p.content); i++ {
		value = (value << 8) | int(p.content[i])
	}
	return value, nil
}

func (p packet) str() string {
	return string(p.content)
}

func (p packet) boolean() bool {
	return len(p.content) > 0 && p.content[0] != 0
}

func berSequence(children ...[]byte) []byte {
	return append([]byte{0x30}, appendLength(bytes.Join(children, nil))...)
}

func berSet(children ...[]byte) []byte {
	return append([]byte{0x31}, appendLength(bytes.Join(children, nil))...)
}

func berOctetString(value string) []byte {
	return append([]byte{0x04}, appendLength([]byte(value))...)
}

func berRawOctetString(value []byte) []byte {
	return append([]byte{0x04}, appendLength(value)...)
}

func berInteger(value int) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(value))
	start := 0
	for start < len(tmp)-1 && tmp[start] == 0 {
		start++
	}
	content := tmp[start:]
	if content[0]&0x80 != 0 {
		content = append([]byte{0x00}, content...)
	}
	return append([]byte{0x02}, appendLength(content)...)
}

func berEnumerated(value int) []byte {
	intBytes := berInteger(value)
	intBytes[0] = 0x0a
	return intBytes
}

func berBoolean(value bool) []byte {
	if value {
		return []byte{0x01, 0x01, 0xff}
	}
	return []byte{0x01, 0x01, 0x00}
}

func berApplication(tag int, content []byte) []byte {
	return append([]byte{byte(0x60 | tag)}, appendLength(content)...)
}

func berContextPrimitive(tag int, content []byte) []byte {
	return append([]byte{byte(0x80 | tag)}, appendLength(content)...)
}

func appendLength(content []byte) []byte {
	length := len(content)
	if length < 0x80 {
		return append([]byte{byte(length)}, content...)
	}
	if length <= 0xff {
		return append([]byte{0x81, byte(length)}, content...)
	}
	return append([]byte{0x82, byte(length >> 8), byte(length)}, content...)
}

func berMessage(messageID int, protocolOp []byte) []byte {
	return berSequence(berInteger(messageID), protocolOp)
}

func expectChildren(pkt packet, count int) error {
	if len(pkt.children) < count {
		return fmt.Errorf("expected at least %d children, got %d", count, len(pkt.children))
	}
	return nil
}
