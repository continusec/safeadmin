package safeadmin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"time"
)

func encrypt(key []byte, in io.Reader, out io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}

	// IV is not a secret, write it out
	_, err = out.Write(iv)
	if err != nil {
		return err
	}

	// And now write the rest...
	_, err = io.Copy(&cipher.StreamWriter{
		S: cipher.NewCTR(block, iv),
		W: out,
	}, in)
	if err != nil {
		return err
	}

	return nil
}

func decrypt(key []byte, in io.Reader, out io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}

	// IV is not a secret, write it out
	_, err = out.Write(iv)
	if err != nil {
		return err
	}

	// And now write the rest...
	_, err = io.Copy(&cipher.StreamWriter{
		S: cipher.NewCTR(block, iv),
		W: out,
	}, in)
	if err != nil {
		return err
	}

	return nil
}

type EncryptHeader struct {
	PublicKey       *rsa.PublicKey // so server can find the right private key
	TTL             time.Time      // after which time the server requires intervention to decrypt
	EncryptedAESKey []byte         // the encrypted key (OAEP)
}

func EncryptWithTTL(rsaPubKey *rsa.PublicKey, ttl time.Time, in io.Reader, out io.Writer) error {
	ttlb := make([]byte, 8)
	binary.BigEndian.PutUint64(ttlb, uint64(ttl.Unix()))

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return err
	}

	oaepResult, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, key, ttlb)
	if err != nil {
		return err
	}

	gobHeaderBuffer := &bytes.Buffer{}
	err = gob.NewEncoder(gobHeaderBuffer).Encode(&EncryptHeader{
		PublicKey:       rsaPubKey,
		TTL:             ttl,
		EncryptedAESKey: oaepResult,
	})
	if err != nil {
		return err
	}
	gbs := gobHeaderBuffer.Bytes()

	// Length prefix the gob or we struggle to read it, since the decoder seems to be greedy
	err = binary.Write(out, binary.BigEndian, uint64(len(gbs)))
	if err != nil {
		return err
	}

	_, err = out.Write(gbs)
	if err != nil {
		return err
	}

	err = encrypt(key, in, out)
	if err != nil {
		return err
	}

	return nil
}

type Oracle interface {
	GetPrivateKey(*EncryptHeader) ([]byte, error)
}

type PrivateKeyOracle struct {
	Key *rsa.PrivateKey
}

func (pko *PrivateKeyOracle) GetPrivateKey(eh *EncryptHeader) ([]byte, error) {
	if time.Now().After(eh.TTL) {
		return nil, errors.New("TTL expired.")
	}

	ttlb := make([]byte, 8)
	binary.BigEndian.PutUint64(ttlb, uint64(eh.TTL.Unix()))

	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pko.Key, eh.EncryptedAESKey, ttlb)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func DecryptWithTTL(keyOracle Oracle, in io.Reader, out io.Writer) error {
	var ehLen uint64
	err := binary.Read(in, binary.BigEndian, &ehLen)
	if err != nil {
		return err
	}

	ehb := make([]byte, ehLen)
	_, err = in.Read(ehb)
	if err != nil {
		return err
	}

	var eh EncryptHeader
	err = gob.NewDecoder(bytes.NewReader(ehb)).Decode(&eh)
	if err != nil {
		return err
	}
	key, err := keyOracle.GetPrivateKey(&eh)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	amt, err := in.Read(iv)
	if amt == len(iv) {
		err = nil // we want to ignore EOF for now
	}
	if err != nil {
		return err
	}
	_, err = io.Copy(out, &cipher.StreamReader{S: cipher.NewCTR(block, iv), R: in})
	if err != nil {
		return err
	}

	return nil
}

func LoadRSAKeyFromCertValidForTime(path string, now time.Time) (*rsa.PublicKey, error) {
	cert, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("No PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("Expected BEGIN CERTIFICATE")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if now.Before(certificate.NotBefore) {
		return nil, errors.New("Cert is not valid before now")
	}
	if now.After(certificate.NotAfter) {
		return nil, errors.New("Cert is not after before now")
	}
	if certificate.PublicKeyAlgorithm != x509.RSA {
		return nil, errors.New("Cert should be RSA algorithm")
	}
	rsaPubKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Cert public key won't cast")
	}
	return rsaPubKey, nil
}

func LoadPrivateRSAKey(path string) (*rsa.PrivateKey, error) {
	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("No PEM block found")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, errors.New("Expected BEGIN PRIVATE KEY")
	}
	pkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rpkey, ok := pkey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("Not an *rsa.PrivateKey")
	}
	return rpkey, nil
}
