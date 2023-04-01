package main

import (
    "crypto/tls"
    "crypto/x509"
    "context"
    "fmt"
    "io/ioutil"
    "github.com/gocql/gocql"
    "os"
    "path/filepath"
    "time"
	  "strings"
	  "flag"
	  "github.com/joho/godotenv"
)

func main() {
    // set default port
    var err error
	
	err = godotenv.Load()

	if os.Getenv("ASTRA_DB_ID") != "" {
		host := []string{os.Getenv("ASTRA_DB_ID"), os.Getenv("ASTRA_DB_REGION")}
		os.Setenv("hostname", strings.Join(host, "-") + ".db.astra.datastax.com")
	}

	cwd,_ := os.Getwd()

	//Flags for command line
	hostnamePtr := flag.String("hostname", os.Getenv("hostname"), "astra hostname") // {ASTRA_DB_ID}-{ASTRA_DB_REGION}.db.astra.datastax.com
	usernamePtr := flag.String("username", "token", "astra username")
	passwordPtr := flag.String("password", os.Getenv("ASTRA_DB_APPLICATION_TOKEN"), "astra Token") //Starts with AstraCS:
	portPtr := flag.Int("port", 29042, "astra port")
	dirPtr := flag.String("ssldir", cwd, "Working directory for SSL files")

	flag.Parse()

    // read command line arguments
	hostname := *hostnamePtr
	username := *usernamePtr
	password := *passwordPtr
	port := *portPtr
	directory := *dirPtr

	caPath,_ := filepath.Abs(directory + "/ca.crt")
	certPath,_ := filepath.Abs(directory + "/cert")
	keyPath,_ := filepath.Abs(directory + "/key")

    // Cluster connection/session code
    cluster := gocql.NewCluster(hostname)
    cluster.Port = port

    // auth
    cluster.Authenticator = gocql.PasswordAuthenticator{
        Username: username,
        Password: password,
    }
	fmt.Println(hostname)
	fmt.Println(certPath)
	fmt.Println(keyPath)
    cert, _ := tls.LoadX509KeyPair(certPath, keyPath)
    caCert, err := ioutil.ReadFile(caPath)
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
        InsecureSkipVerify: true,
    }

    cluster.SslOpts = &gocql.SslOptions{
        Config:                 tlsConfig,
        EnableHostVerification: false,
    }

    // force protocol version 4
    cluster.ProtoVersion = 4

    session, err := cluster.CreateSession()
    if err != nil {
    	  fmt.Println(err)
    }
    defer session.Close()
    ctx := context.Background()
    // connection established

    // define strKey to read
    var strClusterName string
    err2 := session.Query(`SELECT cluster_name FROM system.local`).WithContext(ctx).Scan(&strClusterName)
    if err2 != nil {
        fmt.Println(err)
    } else {
        fmt.Println("cluster_name:", strClusterName)
    }

    // https://stackoverflow.com/questions/17690776/how-to-add-pause-to-a-go-program
    duration := time.Duration(10)*time.Second // Pause for 10 seconds
    time.Sleep(duration)
}
