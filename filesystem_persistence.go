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
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/context"
)

// FilesystemPersistence write key/values to the specified directory.
type FilesystemPersistence struct {
	// Dir is a path to the directory that contains the data
	Dir string

	// Immutable means be read-only
	Immutable bool
}

// Load returns value if found, nil otherwise
func (f *FilesystemPersistence) Load(ctx context.Context, key []byte) ([]byte, error) {
	path := filepath.Join(f.Dir, hex.EncodeToString(key))
	log.Printf("Loading from disk: %s...", path)
	rv, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrStorageKeyNotFound
		}
		return nil, err
	}
	return rv, nil
}

// Save sets value, as atomically as we can. File will be saved with default umask
// This persistence layer ignores the TTL, meaning that keys will be retained indefinitely to allow out of band decryption via breakglass tool
func (f *FilesystemPersistence) Save(ctx context.Context, key, value []byte, ttl time.Time) error {
	if f.Immutable {
		log.Println("Persistence layer is configured as immutable, yet tool is trying to write to it")
		return ErrInvalidConfig
	}

	path := filepath.Join(f.Dir, hex.EncodeToString(key))
	log.Printf("Saving to disk: %s...", path)

	// Create dir if not exists
	_, err := os.Stat(f.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(f.Dir, 0700)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Create temp file
	tf, err := ioutil.TempFile(f.Dir, "temp-")
	if err != nil {
		return err
	}

	// Write it out
	_, err = tf.Write(value)
	if err != nil {
		tf.Close()           // ignore failure
		os.Remove(tf.Name()) // ignore failure
		return err
	}

	// Close it
	err = tf.Close()
	if err != nil {
		os.Remove(tf.Name()) // ignore failure
		return err
	}

	// Rename to correct filename - while not guaranteed by Golang to be atomic, apparently POSIX does on *nix systems
	err = os.Rename(tf.Name(), path)
	if err != nil {
		os.Remove(tf.Name()) // ignore failure
		return err
	}

	return nil
}
