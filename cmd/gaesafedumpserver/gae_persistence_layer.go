package gaesafedumpserver

import (
	"encoding/hex"
	"time"

	"google.golang.org/appengine/datastore"

	context "golang.org/x/net/context"

	"github.com/continusec/safeadmin"
	"github.com/qedus/nds"
)

type safedumpObject struct {
	Key   []byte
	Value []byte
	TTL   int64 // unix time in seconds
}

const (
	dsKind          = "safedumpObject"
	maxQueryResults = 1000 // as recommended by GAE. We expect to only get 1-2 at once, so this shouldn't be a big deal
)

// GoogleCloudDatastorePersistenceLayer persists objects in Google Cloud Datastore,
// with a memcache cache (using qedux/nds)
type GoogleCloudDatastorePersistenceLayer struct{}

// Load returns value if found, nil otherwise
func (g *GoogleCloudDatastorePersistenceLayer) Load(ctx context.Context, key []byte) ([]byte, error) {
	var rv safedumpObject
	err := nds.Get(ctx, datastore.NewKey(ctx, dsKind, hex.EncodeToString(key), 0, nil), &rv)
	switch err {
	case nil:
		return rv.Value, nil
	case datastore.ErrNoSuchEntity:
		return nil, safeadmin.ErrStorageKeyNotFound
	default:
		return nil, err
	}
}

// Save sets value
// The TTL is a suggestion - it is up to the persistence layer whether it chooses to retain longer
func (g *GoogleCloudDatastorePersistenceLayer) Save(ctx context.Context, key, value []byte, ttl time.Time) error {
	_, err := nds.Put(ctx, datastore.NewKey(ctx, dsKind, hex.EncodeToString(key), 0, nil), &safedumpObject{
		Key:   key,
		Value: value,
		TTL:   ttl.Unix(),
	})
	return err
}

// PurgeOldKeys will remove data that is no longer needed
func (g *GoogleCloudDatastorePersistenceLayer) PurgeOldKeys(ctx context.Context) error {
	keys, err := datastore.NewQuery(dsKind).KeysOnly().Filter("TTL <", time.Now().Unix()).Limit(maxQueryResults).GetAll(ctx, nil)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	return nds.DeleteMulti(ctx, keys)
}
