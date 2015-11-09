package main

import (
	"log"
)

var cfg = Config{
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
}

func main() {
	svr, err := NewServer(&cfg)
	if err != nil {
		log.Fatal(err)
	}
	svr.Run()
}
