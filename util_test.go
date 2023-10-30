package hibe_sm9

import (
	"bytes"
	"crypto/rand"
	"golang.org/x/crypto/bn256"
	"testing"
)

func Test_deepClone(t *testing.T) {

	bigInt, g1, _ := bn256.RandomG1(rand.Reader)
	test := deepClone(g1)

	println(bytes.Equal(g1.Marshal(), test.Marshal()))
	println(string(g1.Marshal()))
	println(string(test.Marshal()))
	println(bigInt.String())
}
