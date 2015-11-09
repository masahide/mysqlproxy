package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
)

var (
	cfg = Config{
		Addr:     "127.0.0.1:3311",
		User:     "test",
		Password: "hoge",

		AllowIps: "127.0.0.1",
		Nodes: []NodeConfig{
			{
				Name:     "testdb",
				User:     "root",
				Password: "my-secret-pw",
				Db:       "testdb",
				Addr:     "192.168.99.100:3306",
			},
		},
		ServerCertFile: "server.pem",
		ServerKeyFile:  "server.key",
		ClientCertFile: "client.pem",
		ClientKeyFile:  "client.key",
		TlsAddr:        "127.0.0.1:3443",
	}

	tlsserver = false
	tlsclient = false
)

func init() {
	flag.BoolVar(&tlsserver, "tlsserver", tlsserver, "tlsserver mode")
	flag.BoolVar(&tlsclient, "tlsclient", tlsclient, "tlsclient mode")

}

func main() {
	flag.Parse()

	switch {
	case !tlsserver && !tlsclient:
		svr, err := NewServer(&cfg)
		if err != nil {
			log.Fatal(err)
		}
		svr.Run()
	case tlsserver:
		tlsServer()
	case tlsclient:
		tlsClient()
	}
}

func tlsServer() {
	certificate, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	tlsconfig := tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	tlsconfig.Rand = rand.Reader
	var netlistener net.Listener
	netlistener, err = tls.Listen("tcp", cfg.TlsAddr, &tlsconfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[Server Status] : Tls Listening: %s", cfg.TlsAddr)
	for {
		conn, err := netlistener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	co := new(Conn)
	db := cfg.Nodes[0]
	if err := co.Connect(db.Addr, db.User, db.Password, db.Db); err != nil {
		log.Fatal(err)
	}
	log.Printf("Success Connect. RemoteAddr:%s", co.conn.RemoteAddr())

	done := make(chan bool)
	var once sync.Once
	onceDone := func() {
		log.Printf("done.")
		done <- true
	}
	go func() {
		io.Copy(conn, co.conn)
		once.Do(onceDone)
	}()
	go func() {
		io.Copy(co.conn, conn)
		once.Do(onceDone)
	}()
	<-done
	log.Println("server: conn: closed")
}

func tlsClient() {
	cert_b, _ := ioutil.ReadFile(cfg.ClientCertFile)
	priv_b, _ := ioutil.ReadFile(cfg.ClientKeyFile)
	priv, _ := x509.ParsePKCS1PrivateKey(priv_b)

	config := tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert_b},
			PrivateKey:  priv,
		}},
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", cfg.TlsAddr, &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	log.Print("client: exiting")
}
