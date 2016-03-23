package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/masahide/mysqlproxy"
)

var (
	defaultListenNet  = "tcp"
	defaultListenAddr = "0.0.0.0:9696"
	cfg               mysqlproxy.Config
	cfgs              = map[bool]mysqlproxy.Config{
		true: mysqlproxy.Config{
			Net:  "unix",
			Addr: "mysqlproxy.sock",

			AllowIps:       "@",
			TlsServer:      false,
			TlsClient:      true,
			ClientCertFile: "client.pem",
			ClientKeyFile:  "client.key",
		},
		false: mysqlproxy.Config{
			Net:  defaultListenNet,
			Addr: defaultListenAddr,

			AllowIps:   "",
			TlsServer:  true,
			TlsClient:  false,
			CaCertFile: "ca.pem",
			CaKeyFile:  "ca.key",
		},
	}
	root    *bool   = flag.Bool("root", false, "Serve as root proxy server.")
	workdir *string = flag.String("workdir", "", "Work directory.")
	config  *string = flag.String("config", "", "Config file path.")
	net     *string = flag.String("net", defaultListenNet, "Listen net.")
	addr    *string = flag.String("addr", defaultListenAddr, "Listen address.")
)

func init() {
	flag.Parse()
	cfg = cfgs[*root]
	if *net != cfg.Net {
		cfg.Net = *net
	}
	if *addr != cfg.Addr {
		cfg.Addr = *addr
	}
	if *workdir == "" {
		var err error
		if *workdir, err = os.Getwd(); err != nil {
			log.Fatal(err)
		}
	}
	cfg.ConfigPath = *config
	if cfg.TlsServer {
		cfg.CaCertFile = filepath.Join(*workdir, cfg.CaCertFile)
		cfg.CaKeyFile = filepath.Join(*workdir, cfg.CaKeyFile)
		ca_b, err := ioutil.ReadFile(cfg.CaCertFile)
		if err != nil {
			log.Fatal(err)
		}
		ca, err := x509.ParseCertificate(ca_b)
		if err != nil {
			log.Fatal(err)
		}
		priv_b, err := ioutil.ReadFile(cfg.CaKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		priv, err := x509.ParsePKCS1PrivateKey(priv_b)
		if err != nil {
			log.Fatal(err)
		}
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
		cfg.Addr = filepath.Join(*workdir, cfg.Addr)
		cfg.ClientCertFile = filepath.Join(*workdir, cfg.ClientCertFile)
		cfg.ClientKeyFile = filepath.Join(*workdir, cfg.ClientKeyFile)
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
	svr, err := mysqlproxy.NewServer(&cfg)
	if err != nil {
		log.Fatal(err)
	}
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sc
		log.Printf("main Got signal: %s", sig)
		svr.Close()
	}()
	svr.Run()
}
