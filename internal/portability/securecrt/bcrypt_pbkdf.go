package securecrt

// bcrypt_pbkdf, the OpenBSD key-derivation function SecureCRT's "03:" password
// format uses — the same KDF OpenSSH uses for its encrypted private keys.
//
// This is a vendored copy of golang.org/x/crypto/ssh/internal/bcrypt_pbkdf,
// which is an internal package and so cannot be imported. Same BSD-style
// licence as the rest of x/crypto; the algorithm is the reference OpenBSD
// bcrypt_pbkdf and is not ours to change.
//
// Correctness is not taken on trust: the "03:" password blob embeds a SHA-256
// of the plaintext, so a KDF that is even one byte wrong fails that checksum
// and recovers nothing, rather than producing a plausible wrong password.

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blowfish"
)

const bcryptPBKDFBlockSize = 32

// bcryptPBKDF derives keyLen bytes from password and salt over the given
// number of rounds.
func bcryptPBKDF(password, salt []byte, keyLen, rounds int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: too few rounds")
	}
	if len(password) == 0 {
		return nil, errors.New("bcrypt_pbkdf: empty password")
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return nil, errors.New("bcrypt_pbkdf: bad salt length")
	}
	if keyLen <= 0 || keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: bad key length")
	}

	numBlocks := (keyLen + bcryptPBKDFBlockSize - 1) / bcryptPBKDFBlockSize
	out := make([]byte, numBlocks*bcryptPBKDFBlockSize)

	sha2pass := sha512.Sum512(password)

	var countSalt [4]byte
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(countSalt[:], uint32(block)) // #nosec G115 -- block is small

		h := sha512.New()
		h.Write(salt)
		h.Write(countSalt[:])
		sha2salt := h.Sum(nil)

		tmp := bcryptHash(sha2pass[:], sha2salt)
		out2 := make([]byte, len(tmp))
		copy(out2, tmp)

		for i := 2; i <= rounds; i++ {
			h := sha512.New()
			h.Write(tmp)
			sha2salt = h.Sum(nil)
			tmp = bcryptHash(sha2pass[:], sha2salt)
			for j := range out2 {
				out2[j] ^= tmp[j]
			}
		}

		// Interleave: byte i of this block lands at stride numBlocks, so the
		// blocks are woven together the way OpenBSD writes them.
		for i := range out2 {
			out[i*numBlocks+(block-1)] = out2[i]
		}
	}

	return out[:keyLen], nil
}

var bcryptMagic = []byte("OxychromaticBlowfishSwatDynamite")

// bcryptHash is the fixed 64-round EksBlowfish core.
func bcryptHash(sha2pass, sha2salt []byte) []byte {
	c, err := blowfish.NewSaltedCipher(sha2pass, sha2salt)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(sha2salt, c)
		blowfish.ExpandKey(sha2pass, c)
	}

	cdata := make([]uint32, bcryptPBKDFBlockSize/4)
	for i := range cdata {
		cdata[i] = binary.BigEndian.Uint32(bcryptMagic[i*4 : i*4+4])
	}

	// Encrypt the magic, in place, 64 times. Blowfish works on 64-bit blocks,
	// so each pass runs the ECB over consecutive uint32 pairs.
	var buf [8]byte
	for i := 0; i < 64; i++ {
		for j := 0; j < len(cdata); j += 2 {
			binary.BigEndian.PutUint32(buf[0:4], cdata[j])
			binary.BigEndian.PutUint32(buf[4:8], cdata[j+1])
			c.Encrypt(buf[:], buf[:])
			cdata[j] = binary.BigEndian.Uint32(buf[0:4])
			cdata[j+1] = binary.BigEndian.Uint32(buf[4:8])
		}
	}

	// Output is little-endian, which is the OpenBSD byte order for this step.
	out := make([]byte, bcryptPBKDFBlockSize)
	for i, v := range cdata {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}
