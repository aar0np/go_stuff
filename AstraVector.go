package main

import (
	"fmt"
	"os"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	gocqlastra "github.com/datastax/gocql-astra"
)

func main() {

	AstraDBID := os.Getenv("ASTRA_DB_ID")
	Token := os.Getenv("ASTRA_DB_APPLICATION_TOKEN")
	Keyspace := os.Getenv("ASTRA_DB_KEYSPACE")

	cluster, err1 := gocqlastra.NewClusterFromURL("https://api.astra.datastax.com", AstraDBID, Token, 10*time.Second)

	if err1 != nil {
		fmt.Printf("unable to connect to Astra cluster: %w", err1)
	}

	cluster.Keyspace = Keyspace
	cluster.ProtoVersion = 4

	session, err2 := cluster.CreateSession()

	if err2 != nil {
		fmt.Printf("unable to create Astra session: %w", err2)
	}

	//var selectFixVec []float32
	//ctx := context.Background()
	var selectFixVec gocql.VectorType

	iter := session.Query("SELECT content_features FROM videos WHERE videoid = ?", "8926e6d1-c09d-4f96-92a7-415b5a887233").Iter()

	for iter.Scan(&selectFixVec) {
		fmt.Println("content_features:", selectFixVec)
	}

	if err := iter.Close(); err != nil {
		fmt.Printf("error: {w%}", err)
	}
}
