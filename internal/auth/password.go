package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonVariant = "argon2id"
	argonVersion = 19
	argonMemory  = 64 * 1024
	argonTime    = 1
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVariant,
		argonVersion,
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(phc, password string) (bool, error) {
	params, salt, expected, err := parsePHC(phc)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

type phcParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func parsePHC(phc string) (phcParams, []byte, []byte, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != argonVariant {
		return phcParams{}, nil, nil, errors.New("invalid PHC string")
	}

	versionPart := strings.TrimPrefix(parts[2], "v=")
	version, err := strconv.Atoi(versionPart)
	if err != nil || version != argonVersion {
		return phcParams{}, nil, nil, errors.New("unsupported argon2 version")
	}

	var params phcParams
	for _, piece := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(piece, "=", 2)
		if len(kv) != 2 {
			return phcParams{}, nil, nil, errors.New("invalid argon2 parameter")
		}
		value, err := strconv.Atoi(kv[1])
		if err != nil {
			return phcParams{}, nil, nil, err
		}
		switch kv[0] {
		case "m":
			params.memory = uint32(value)
		case "t":
			params.time = uint32(value)
		case "p":
			params.threads = uint8(value)
		default:
			return phcParams{}, nil, nil, errors.New("unknown argon2 parameter")
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return phcParams{}, nil, nil, err
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return phcParams{}, nil, nil, err
	}
	return params, salt, hash, nil
}
