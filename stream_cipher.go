/*

Copyright 2017 Continusec Pty Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package safeadmin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"io/ioutil"
	"regexp"
	"time"

	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
)

var (
	fragmentStart  = []byte("<ENCRYPTED:")
	fragmentEnd    = []byte(">")
	encryptedRegex = regexp.MustCompile("<ENCRYPTED:[^>]+>")
)

// EncryptWithTTL will generate a symmetric key, then encrypt this using the specified public key and TTL,
// write this out, and then apply a stream cipher to in, copying to out. The number of bytes written to out
// will be the same as those written to in with a small constant number of bytes added to it.
// If chunk is set, then output is suitable for embedded in a larger file (e.g. log file)
func EncryptWithTTL(rsaPubKey *rsa.PublicKey, spki []byte, ttl time.Time, in io.Reader, out io.Writer, chunk bool) error {
	var output io.Writer
	var encoder io.WriteCloser
	if chunk {
		_, err := out.Write(fragmentStart)
		if err != nil {
			return err
		}
		encoder = base64.NewEncoder(base64.StdEncoding, out)
		output = encoder
	} else {
		output = out
	}

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

	gbs, err := proto.Marshal(&pb.EncryptedHeader{
		Ttl:             ttl.Unix(),
		EncryptedKey:    oaepResult,
		SpkiFingerprint: spki,
	})
	if err != nil {
		return err
	}

	// Length prefix the gob or we struggle to read it, since the decoder seems to be greedy
	err = binary.Write(output, binary.BigEndian, uint64(len(gbs)))
	if err != nil {
		return err
	}

	_, err = output.Write(gbs)
	if err != nil {
		return err
	}

	// Now, let's actually do the encryption
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
	_, err = output.Write(iv)
	if err != nil {
		return err
	}

	// And now write the rest...
	_, err = io.Copy(&cipher.StreamWriter{
		S: cipher.NewCTR(block, iv),
		W: output,
	}, in)
	if err != nil {
		return err
	}

	if chunk {
		err = encoder.Close() // must be called to flush bytes, won't close underlying
		if err != nil {
			return err
		}
		_, err = out.Write(fragmentEnd)
		if err != nil {
			return err
		}
	}

	return nil
}

// DecryptWithTTL reads an encrypted header, sends it to the oracle to get the private key material,
// then decryptes the stream, copying to out. Note that since we don't MAC, we make no guarantees about
// integrity or authentication.
// If chunks is set, then look for chunks to decode as part of a larger file, instead of the whole stream.
// For now, if fragments is set, then the entire input stream is read before processing commences.
func DecryptWithTTL(keyOracle Oracle, in io.Reader, out io.Writer, chunks bool) error {
	if chunks {
		dataIn, err := ioutil.ReadAll(in)
		if err != nil {
			return err
		}
		_, err = out.Write(encryptedRegex.ReplaceAllFunc(dataIn, func(b []byte) []byte {
			decoded, err := base64.StdEncoding.DecodeString(string(b[len(fragmentStart) : len(b)-len(fragmentEnd)]))
			if err != nil {
				// Error base64 decoding encrypted chunk, returning encrypted instead since we can't report an error
				return b
			}

			rv := &bytes.Buffer{}
			err = decryptRaw(keyOracle, bytes.NewReader(decoded), rv)
			if err != nil {
				// Error decrytping chunk, returning encrypted instead since we can't report an error
				return b
			}

			return rv.Bytes()
		}))
		if err != nil {
			return err
		}
		return nil
	} else {
		return decryptRaw(keyOracle, in, out)
	}

}

func decryptRaw(keyOracle Oracle, in io.Reader, out io.Writer) error {
	var ehLen uint64
	err := binary.Read(in, binary.BigEndian, &ehLen)
	if err != nil {
		return err
	}

	if ehLen > 100000 { // sanity check, should be much smaller
		return ErrUnexpectedLengthOfBlock
	}

	ehb := make([]byte, ehLen)
	_, err = in.Read(ehb)
	if err != nil {
		return err
	}

	eh := &pb.EncryptedHeader{}
	err = proto.Unmarshal(ehb, eh)
	if err != nil {
		return err
	}

	key, err := keyOracle.GetPrivateKey(eh)
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
