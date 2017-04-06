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
	"encoding/binary"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/context"
)

const (
	fnamePrefix = "sdd"
)

// FilesystemPersistence write key/values to the specified directory.
type FilesystemPersistence struct {
	// Dir is a path to the directory that contains the data
	Dir string

	// Immutable means be read-only
	Immutable bool
}

// Load returns value if found, nil otherwise. It should ignore the TTL
func (f *FilesystemPersistence) Load(ctx context.Context, key []byte) ([]byte, error) {
	rv, err := ioutil.ReadFile(filepath.Join(f.Dir, fnamePrefix+hex.EncodeToString(key)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrStorageKeyNotFound
		}
		return nil, err
	}
	// Check we have the TTL
	if len(rv) < 8 {
		return nil, ErrInternalError
	}

	// We don't actually care what it is though
	return rv[8:], nil
}

// Save sets value, as atomically as we can. File will be saved with default umask
// This persistence layer saves the TTL as a prefix to each file
func (f *FilesystemPersistence) Save(ctx context.Context, key, value []byte, ttl time.Time) error {
	if f.Immutable {
		log.Println("Persistence layer is configured as immutable, yet tool is trying to write to it")
		return ErrInvalidConfig
	}

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

	// Write out TTL first
	err = binary.Write(tf, binary.BigEndian, uint64(ttl.Unix()))
	if err != nil {
		tf.Close()           // ignore failure
		os.Remove(tf.Name()) // ignore failure
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
	err = os.Rename(tf.Name(), filepath.Join(f.Dir, fnamePrefix+hex.EncodeToString(key)))
	if err != nil {
		os.Remove(tf.Name()) // ignore failure
		return err
	}

	return nil
}

func deleteIfOld(fpath string, now uint64) error {
	// Open the file
	f, err := os.Open(fpath)
	if err != nil {
		return err
	}

	// Read TTL
	var ttl uint64
	err = binary.Read(f, binary.BigEndian, &ttl)
	f.Close() // no matter what, we close the file now and don't care if it doesn't work
	if err != nil {
		return err
	}

	// If too old, delete it
	if ttl < now {
		return os.Remove(fpath)
	}

	return nil
}

// Purge removes data whose TTL is older than now
func (f *FilesystemPersistence) Purge(ctx context.Context, now time.Time) error {
	files, err := ioutil.ReadDir(f.Dir)
	if err != nil {
		return err
	}
	nowInt := uint64(now.Unix())
	for _, fi := range files {
		name := fi.Name()
		if strings.HasPrefix(name, fnamePrefix) {
			fileErr := deleteIfOld(filepath.Join(f.Dir, name), nowInt)
			if fileErr != nil {
				log.Printf("Error checking %s for deletion, continuing to next file: %s\n", name, fileErr)
				err = fileErr // deliberately do not terminate, instead save error for returning later
			}
		}
	}
	return err
}
