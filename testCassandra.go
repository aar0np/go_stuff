package main

import (
    "context"
    "fmt"
    "github.com/gocql/gocql"
    "os"
    "strconv"
    "time"
)

func main() {
    // set default port
    var port int = 9042
    var err error

    // read command line arguments
    hostname := os.Args[1]
    username := os.Args[2]
    password := os.Args[3]

    // debug
    //fmt.Println("args == ",len(os.Args))

    if len(os.Args) > 4 {
        port,err = strconv.Atoi(os.Args[4])
    }

    // Cluster connection/session code
    cluster := gocql.NewCluster(hostname)
    cluster.Port = port

    // auth
    cluster.Authenticator = gocql.PasswordAuthenticator{
        Username: username,
        Password: password,
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

    // define columns to read
    var strClusterName           string
    var strBroadcastAddress      string
    var strNativeProtocolVersion string
    var strReleaseVersion        string
    var strSchemaVersion         string

    // define query string
    strCQL := "SELECT cluster_name,broadcast_address,native_protocol_version,release_version,schema_version FROM system.local"

    err2 := session.Query(strCQL).WithContext(ctx).Scan(&strClusterName,&strBroadcastAddress,&strNativeProtocolVersion,&strReleaseVersion,&strSchemaVersion)
    if err2 != nil {
        fmt.Println(err)
    } else {
        fmt.Println("cluster_name:", strClusterName)
        fmt.Println("broadcast_address:", strBroadcastAddress)
        fmt.Println("native_protocol_version:", strNativeProtocolVersion)
        fmt.Println("release_version:", strReleaseVersion)
        fmt.Println("schema_version:", strSchemaVersion)
    }

    // https://stackoverflow.com/questions/17690776/how-to-add-pause-to-a-go-program
    duration := time.Duration(10)*time.Second // Pause for 10 seconds
    time.Sleep(duration)
}
