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

package main

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/continusec/safeadmin"
	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
)

func mustParseDuration(s string) time.Duration {
	rv, err := time.ParseDuration(s)
	if err != nil {
		log.Fatalf("Unable to parse duration: %s\n", err)
	}
	return rv
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Please specify a config file for the server to use.")
	}

	confData, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Error reading server configuration: %s\n", err)
	}

	conf := &pb.ServerConfig{}
	err = proto.UnmarshalText(string(confData), conf)
	if err != nil {
		log.Fatalf("Error parsing server configuration: %s\n", err)
	}

	tc, err := credentials.NewServerTLSFromFile(conf.ServerCertPath, conf.ServerKeyPath)
	if err != nil {
		log.Fatalf("Error reading server keys/certs: %s\n", err)
	}

	lis, err := net.Listen(conf.ListenProtocol, conf.ListenBind)
	if err != nil {
		log.Fatalf("Error establishing server listener: %s\n", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(tc))
	pb.RegisterSafeDumpServiceServer(grpcServer, &safeadmin.SafeDumpServer{
		Storage:                   &safeadmin.FilesystemPersistence{Dir: conf.ArchivedKeysDir},
		MaxDecryptionPeriod:       mustParseDuration(conf.MaxDecryptionPeriod),
		CertificateRotationPeriod: mustParseDuration(conf.CertificateRotationPeriod),
	})

	log.Println("Serving...")
	grpcServer.Serve(lis)
}
