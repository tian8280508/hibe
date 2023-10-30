package hibe_sm9

// var pairing = pbc.GenerateA(160, 512).NewPairing()

// HIBE specifies a general interface for HIBE constructions.
type HIBE interface {
	// Setup creates a new HIBE instance returning the public parameters and the root entity.
	Setup(seed []byte) (params, root []byte, err error)
	// Extract creates a new entity specified by an id from a given ancestor entity.
	Extract(ancestor, id []byte) ([]byte, error)
	// Encrypt enciphers a given message with the public key specified by an entity id.
	// Note, that for simplicity reasons the ciphertext has to be split into two parts (c1, c2).
	Encrypt(params, msg []byte, id [][]byte) (c1, c2 []byte, err error)
	// Decrypt deciphers a ciphertext pair with the secret key of an entity.
	Decrypt(entity, c1, c2 []byte) ([]byte, error)
}
