package ppk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// pemBlock is encoding/pem's block under a local name, so the encoder above
// reads without a second import path in mind.
type pemBlock = pem.Block

// signer rebuilds a Go private key from the two halves of the file.
//
// PuTTY splits a key into a public half and a private half, each a sequence of
// SSH wire-format values. The values are the same numbers OpenSSH stores, but
// in a different order and a different grouping, so this is a re-assembly:
// read both halves, put the pieces back together, and hand the result to the
// standard encoder. Nothing is recomputed or re-derived.
func (k *Key) signer() (crypto.Signer, error) {
	switch k.Algorithm {
	case ssh.KeyAlgoED25519:
		return k.ed25519()
	case ssh.KeyAlgoRSA:
		return k.rsa()
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return k.ecdsa()
	case ssh.KeyAlgoDSA:
		return nil, errors.New("ppk: DSA keys are obsolete and refused by current OpenSSH; " +
			"generate a replacement rather than migrating this one")
	default:
		return nil, fmt.Errorf("ppk: %s keys are not supported", k.Algorithm)
	}
}

func (k *Key) ed25519() (crypto.Signer, error) {
	pub := newReader(k.public)
	if _, err := pub.string(); err != nil { // the algorithm name, already known
		return nil, err
	}
	publicBytes, err := pub.string()
	if err != nil {
		return nil, err
	}

	priv := newReader(k.private)
	seed, err := priv.string()
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ppk: the ed25519 private half is %d bytes, want %d",
			len(seed), ed25519.SeedSize)
	}

	key := ed25519.NewKeyFromSeed(seed)

	// The two halves are stored independently, so a file can disagree with
	// itself — through corruption, or through an edit meant to make a key
	// look like someone else's. A key whose public half is not the one its
	// private half generates must not be imported under that identity.
	if !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(publicBytes)) {
		return nil, errors.New("ppk: the public and private halves are not the same key")
	}
	return key, nil
}

func (k *Key) rsa() (crypto.Signer, error) {
	pub := newReader(k.public)
	if _, err := pub.string(); err != nil {
		return nil, err
	}
	e, err := pub.mpint()
	if err != nil {
		return nil, err
	}
	n, err := pub.mpint()
	if err != nil {
		return nil, err
	}

	priv := newReader(k.private)
	d, err := priv.mpint()
	if err != nil {
		return nil, err
	}
	p, err := priv.mpint()
	if err != nil {
		return nil, err
	}
	q, err := priv.mpint()
	if err != nil {
		return nil, err
	}

	if !e.IsInt64() || e.Int64() < 3 {
		return nil, fmt.Errorf("ppk: the RSA exponent %s is not usable", e)
	}
	if n.BitLen() < 1024 {
		return nil, fmt.Errorf("ppk: this RSA key is %d bits, too short to import", n.BitLen())
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	// Validate checks p*q == n and that d really inverts e, so a file whose
	// halves do not belong together is caught here rather than at first use
	// against a real host.
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("ppk: the RSA key does not check out: %w", err)
	}
	key.Precompute()
	return key, nil
}

func (k *Key) ecdsa() (crypto.Signer, error) {
	pub := newReader(k.public)
	if _, err := pub.string(); err != nil {
		return nil, err
	}
	curveName, err := pub.string()
	if err != nil {
		return nil, err
	}
	point, err := pub.string()
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	switch string(curveName) {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("ppk: unsupported curve %q", curveName)
	}

	x, y := elliptic.Unmarshal(curve, point) //nolint:staticcheck // the wire format is uncompressed points
	if x == nil {
		return nil, errors.New("ppk: the public point is not on the named curve")
	}

	priv := newReader(k.private)
	d, err := priv.mpint()
	if err != nil {
		return nil, err
	}
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("ppk: the ECDSA private scalar is out of range")
	}

	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}

	// As with ed25519: the halves are stored separately, so check that the
	// point really is this scalar's.
	checkX, checkY := curve.ScalarBaseMult(d.Bytes())
	if checkX.Cmp(x) != 0 || checkY.Cmp(y) != 0 {
		return nil, errors.New("ppk: the public and private halves are not the same key")
	}
	return key, nil
}

// --- SSH wire format ---------------------------------------------------------

// reader walks a sequence of length-prefixed SSH values.
type reader struct {
	data []byte
	pos  int
}

func newReader(data []byte) *reader { return &reader{data: data} }

func (r *reader) string() ([]byte, error) {
	if r.pos+4 > len(r.data) {
		return nil, errors.New("ppk: the key data ends mid-value")
	}
	length := int(r.data[r.pos])<<24 | int(r.data[r.pos+1])<<16 |
		int(r.data[r.pos+2])<<8 | int(r.data[r.pos+3])
	r.pos += 4

	// The length is read from the file, so it is checked against what is
	// actually there rather than trusted to be sane.
	if length < 0 || r.pos+length > len(r.data) {
		return nil, fmt.Errorf("ppk: a value claims %d bytes and only %d remain",
			length, len(r.data)-r.pos)
	}
	out := r.data[r.pos : r.pos+length]
	r.pos += length
	return out, nil
}

func (r *reader) mpint() (*big.Int, error) {
	raw, err := r.string()
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 && raw[0]&0x80 != 0 {
		return nil, errors.New("ppk: a negative integer where a key component was expected")
	}
	return new(big.Int).SetBytes(raw), nil
}
