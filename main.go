package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
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
		TlsServer:      false,
		TlsClient:      false,
		CaCertFile:     "ca.pem",
		CaKeyFile:      "ca.key",
		ClientCertFile: "client.pem",
		ClientKeyFile:  "client.key",
	}

	tlsserver = false
	tlsclient = false
)

func init() {

	if cfg.TlsServer {
		ca_b, _ := ioutil.ReadFile(cfg.CaCertFile)
		ca, _ := x509.ParseCertificate(ca_b)
		priv_b, _ := ioutil.ReadFile(cfg.CaKeyFile)
		priv, _ := x509.ParsePKCS1PrivateKey(priv_b)

		pool := x509.NewCertPool()
		pool.AddCert(ca)

		cert := tls.Certificate{
			Certificate: [][]byte{ca_b},
			PrivateKey:  priv,
		}

		cfg.TlsServerConf = &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
		}
		cfg.TlsServerConf.Rand = rand.Reader
	}
	if cfg.TlsClient {
		cert_b, err := ioutil.ReadFile(cfg.ClientCertFile)
		if err != nil {
			log.Fatal(err)
		}
		priv_b, err := ioutil.ReadFile(cfg.ClientKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		priv, err := x509.ParsePKCS1PrivateKey(priv_b)
		if err != nil {
			log.Fatal(err)
		}
		cfg.TlsClientConf = &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{cert_b},
				PrivateKey:  priv,
			}},
			InsecureSkipVerify: true,
		}
	}

}

func main() {
	svr, err := NewServer(&cfg)
	if err != nil {
		log.Fatal(err)
	}
	svr.Run()
}
