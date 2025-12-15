package main

import (
	"fmt"
	"os"
	"path/filepath"

	apachegocql "github.com/apache/cassandra-gocql-driver/v2"
)

func main() {

	Token := os.Getenv("ASTRA_DB_APPLICATION_TOKEN")
	Keyspace := os.Getenv("ASTRA_DB_KEYSPACE")
	scbDir := os.Getenv("ASTRA_DB_SCB_DIR")
	hostname := os.Getenv("ASTRA_DB_HOSTNAME")

	port := 29042
	username := "token"
	password := Token

	caPath, _ := filepath.Abs(scbDir + "ca.crt")
	certPath, _ := filepath.Abs(scbDir + "cert")
	keyPath, _ := filepath.Abs(scbDir + "key")

	cluster := apachegocql.NewCluster(hostname)
	cluster.Port = port
	cluster.Keyspace = Keyspace

	cluster.Authenticator = apachegocql.PasswordAuthenticator{
		Username: username,
		Password: password,
	}

	cluster.SslOpts = &apachegocql.SslOptions{
		CertPath:               certPath,
		KeyPath:                keyPath,
		CaPath:                 caPath,
		EnableHostVerification: false,
	}

	cluster.Keyspace = Keyspace
	cluster.ProtoVersion = 4

	session, err2 := cluster.CreateSession()

	if err2 != nil {
		fmt.Printf("unable to create Astra session: {%w}", err2)
	}

	defer session.Close()

	var selectFixVec []float32

	err3 := session.Query("SELECT content_features FROM videos WHERE videoid = ?", "8926e6d1-c09d-4f96-92a7-415b5a887233").Scan(&selectFixVec)

	if err3 != nil {
		fmt.Printf("query error %w", err3)
	} else {
		fmt.Println("content_features:", selectFixVec)
	}
}
