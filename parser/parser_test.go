package parser

import (
	"log"
	"testing"
)

func TestParse(t *testing.T) {
	want := map[string]*ProxyUser{
		"user1": &ProxyUser{
			Username:    "hoge",
			Password:    "fuga",
			ProxyServer: "201.34.33.44",
		},
		"user2": &ProxyUser{
			Username:    "hoge",
			Password:    "fuga",
			ProxyServer: "201.34.33.44",
		},
	}
	p := &Parser{
		ConfigPath: "mysqlproxy.toml",
	}
	got, err := p.Parse()
	if err != nil {
		t.Fatal(err)
	}
	for key, w := range want {
		g, ok := got[key]
		if !ok {
			t.Fatal("key(%s) is not exists in got(%#v)", key, got)
		}
		if w != g {
			log.Fatalf("Error:\n\tw: %s\n\tg: %s\n", w, g)
		}
	}
}
