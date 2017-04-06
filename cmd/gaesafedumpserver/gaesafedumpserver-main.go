package gaesafedumpserver

import (
	"net/http"
	"time"

	"io/ioutil"

	"github.com/continusec/safeadmin"
	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
	"google.golang.org/appengine"
)

func init() {
	persistenceLayer := &GoogleCloudDatastorePersistenceLayer{}
	server := &safeadmin.SafeDumpServer{
		Storage:                   persistenceLayer,
		MaxDecryptionPeriod:       time.Hour * 24 * 7,
		CertificateRotationPeriod: time.Hour * 24,
	}

	http.HandleFunc("/simpleRPC/GetPublicCert", func(w http.ResponseWriter, r *http.Request) {
		req := &pb.GetPublicCertRequest{}
		if commonStart(w, r, req) {
			resp, err := server.GetPublicCert(appengine.NewContext(r), req)
			commonEnd(w, resp, err)
		}
	})
	http.HandleFunc("/simpleRPC/DecryptSecret", func(w http.ResponseWriter, r *http.Request) {
		req := &pb.DecryptSecretRequest{}
		if commonStart(w, r, req) {
			resp, err := server.DecryptSecret(appengine.NewContext(r), req)
			commonEnd(w, resp, err)
		}
	})
	http.HandleFunc("/tasks/PurgeOldKeys", func(w http.ResponseWriter, r *http.Request) {
		err := persistenceLayer.PurgeOldKeys(appengine.NewContext(r))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}

// commonStart reads the POST data, and unmarshals into the given message
// Returns True if ready to go. If error occurs, error message is sent
// and returns False
func commonStart(w http.ResponseWriter, r *http.Request, req proto.Message) bool {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	defer r.Body.Close()
	input, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	err = proto.Unmarshal(input, req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	return true
}

// commonEnd marshals the proto, and writes it out, if the given error is clean
func commonEnd(w http.ResponseWriter, resp proto.Message, err error) {
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	output, err := proto.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(output) // ignore error, too late anyway
}
