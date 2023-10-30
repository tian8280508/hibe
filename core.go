package hibe_sm9

import (
	"crypto/rand"
	"golang.org/x/crypto/bn256"
	"io"
	"math/big"
)

// Params represents the system parameters for a hierarchy.
type Params struct {
	G  *bn256.G2
	G1 *bn256.G2
	G2 *bn256.G1
	G3 *bn256.G1
	H  []*bn256.G1

	// Some cached state
	Pairing *bn256.GT
}

// MasterKey represents the key for a hierarchy that can create a key for any
// element.
type MasterKey *bn256.G1

// MaximumDepth returns the maximum depth of the hierarchy. This was specified
// via the "l" argument when Setup was called.
func (params *Params) MaximumDepth() int {
	return len(params.H)
}

// PrivateKey represents a key for an ID in a hierarchy that can decrypt
// messages encrypted with that ID and issue keys for children of that ID in
// the hierarchy.
type PrivateKey struct {
	A0 *bn256.G1
	A1 *bn256.G2
	B  []*bn256.G1
}

// Ciphertext represents an encrypted message.
type Ciphertext struct {
	A *bn256.GT
	B *bn256.G2
	C *bn256.G1
}

// DepthLeft returns the maximum depth of descendants in the hierarchy whose
// keys can be generated from this one.
func (privkey *PrivateKey) DepthLeft() int {
	return len(privkey.B)
}

// Setup generates the system parameters, (hich may be made visible to an
// adversary. The parameter "l" is the maximum depth that the hierarchy will
// support.
func Setup(random io.Reader, l int) (*Params, MasterKey, error) {
	// 1.
	params := &Params{}
	var err error

	// The algorithm technically needs g to be a generator of G, but since G is
	// isomorphic to Zp, any element in G is technically a generator. So, we
	// just choose a random element.
	_, params.G, err = bn256.RandomG2(random)
	if err != nil {
		return nil, nil, err
	}

	// Choose a random alpha in Zp.
	alpha, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	// Choose g1 = g ^ alpha.
	params.G1 = new(bn256.G2).ScalarMult(params.G, alpha)

	// Randomly choose g2 and g3.
	_, params.G2, err = bn256.RandomG1(random)
	if err != nil {
		return nil, nil, err
	}
	_, params.G3, err = bn256.RandomG1(random)
	if err != nil {
		return nil, nil, err
	}

	// Randomly choose h1 ... hl.
	params.H = make([]*bn256.G1, l, l)
	for i := range params.H {
		_, params.H[i], err = bn256.RandomG1(random)
		if err != nil {
			return nil, nil, err
		}
	}

	// Compute the master key as g2 ^ alpha.
	master := new(bn256.G1).ScalarMult(params.G2, alpha)

	return params, master, nil
}

// KeyGenFromMaster generates a key for an ID using the master key.
func KeyGenFromMaster(random io.Reader, params *Params, master MasterKey, id []*big.Int) (*PrivateKey, error) {
	// 1. 私钥的三个参数是什么意思
	// 2. id []*big.Int 就是身份id ，用数组表达身份标识的原因
	// 3. r的作用，加噪?
	// 4. ScalarMult 功能是椭圆曲线的乘法，需要找到SM9的实现中对应的函数是什么 ，可能是WrapKey
	// 5. 终极目标：给一个实际的案例，参数赋值后，然后怎么计算
	key := &PrivateKey{}
	k := len(id)
	l := len(params.H)
	if k > l {
		panic("Cannot generate key at greater than maximum depth.")
	}

	// Randomly choose r in Zp.
	r, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, err
	}

	product := deepClone(params.G3)
	for i := 0; i != k; i++ {
		h := new(bn256.G1).ScalarMult(params.H[i], id[i])
		product.Add(product, h)
	}
	product.ScalarMult(product, r)

	key.A0 = new(bn256.G1).Add(master, product)
	key.A1 = new(bn256.G2).ScalarMult(params.G, r)
	key.B = make([]*bn256.G1, l-k)
	for j := 0; j != l-k; j++ {
		key.B[j] = new(bn256.G1).ScalarMult(params.H[k+j], r)
	}

	return key, nil
}

// KeyGenFromParent generates a key for an ID using the private key of the
// parent of ID in the hierarchy. Using a different parent will result in
// undefined behavior.
func KeyGenFromParent(random io.Reader, params *Params, parent *PrivateKey, id []*big.Int) (*PrivateKey, error) {
	key := &PrivateKey{}
	k := len(id)
	l := len(params.H)
	if k > l {
		panic("Cannot generate key at greater than maximum depth")
	}
	if parent.DepthLeft() != l-k+1 {
		panic("Trying to generate key at depth that is not the child of the provided parent")
	}

	// Randomly choose t in Zp
	t, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, err
	}

	product := deepClone(params.G3)
	for i := 0; i != k; i++ {
		h := new(bn256.G1).ScalarMult(params.H[i], id[i])
		product.Add(product, h)
	}
	product.ScalarMult(product, t)

	bpower := new(bn256.G1).ScalarMult(parent.B[0], id[k-1])

	key.A0 = new(bn256.G1).Add(parent.A0, bpower)
	key.A0.Add(key.A0, product)

	key.A1 = new(bn256.G2).ScalarMult(params.G, t)
	key.A1.Add(parent.A1, key.A1)

	key.B = make([]*bn256.G1, l-k)
	for j := 0; j != l-k; j++ {
		key.B[j] = new(bn256.G1).ScalarMult(params.H[k+j], t)
		key.B[j].Add(parent.B[j+1], key.B[j])
	}

	return key, nil
}

// Precache forces "cached params" to be computed. Normally, they are computed
// on the fly, but that is not thread-safe. If you plan to call functions
// (especially Encrypt) multiple times concurrently, you should call this first,
// to eliminate race conditions.
func (params *Params) Precache() {
	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}
}

// Encrypt converts the provided message to ciphertext, using the provided ID
// as the public key.
func Encrypt(random io.Reader, params *Params, id []*big.Int, message *bn256.GT) (*Ciphertext, error) {
	ciphertext := &Ciphertext{}
	k := len(id)

	// Randomly choose s in Zp
	s, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, err
	}

	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}

	ciphertext.A = new(bn256.GT)
	ciphertext.A.ScalarMult(params.Pairing, s)
	ciphertext.A.Add(ciphertext.A, message)

	ciphertext.B = new(bn256.G2).ScalarMult(params.G, s)

	ciphertext.C = deepClone(params.G3)
	for i := 0; i != k; i++ {
		h := new(bn256.G1).ScalarMult(params.H[i], id[i])
		ciphertext.C.Add(ciphertext.C, h)
	}
	ciphertext.C.ScalarMult(ciphertext.C, s)

	return ciphertext, nil
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key.
func Decrypt(key *PrivateKey, ciphertext *Ciphertext) *bn256.GT {
	plaintext := bn256.Pair(ciphertext.C, key.A1)
	invdenominator := new(bn256.GT).Neg(bn256.Pair(key.A0, ciphertext.B))
	plaintext.Add(plaintext, invdenominator)
	plaintext.Add(ciphertext.A, plaintext)
	return plaintext
}
