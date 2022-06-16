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
    "strconv"
    "time"
)

func main() {
    // set default port
    var port int = 29042
    var err error

    // read command line arguments
    hostname := os.Args[1]
    username := os.Args[2]
    password := os.Args[3]

    caPath,_ := filepath.Abs(os.Args[4])
    certPath,_ := filepath.Abs(os.Args[5])
    keyPath,_ := filepath.Abs(os.Args[6])

    if (len(os.Args) > 7) {
		    port,_ = strconv.Atoi(os.Args[7])
    }

    // Cluster connection/session code
    cluster := gocql.NewCluster(hostname)
    cluster.Port = port

    // auth
    cluster.Authenticator = gocql.PasswordAuthenticator{
        Username: username,
        Password: password,
    }

    cert, _ := tls.LoadX509KeyPair(certPath, keyPath)
    caCert, err := ioutil.ReadFile(caPath)
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
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
