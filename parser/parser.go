package parser

import "github.com/masahide/toml"

type Parser struct {
	ConfigPath string
}

type ProxyUser struct {
	Username    string `toml:"username"`
	Password    string `toml:"password"`
	ProxyServer string `toml:"proxyserver"`
}

func (p *Parser) Parse() (map[string]*ProxyUser, error) {
	proxyUsers := make(map[string]*ProxyUser)
	_, err := toml.DecodeFile(p.ConfigPath, &proxyUsers)
	if err != nil {
		return nil, err
	}
	return proxyUsers, nil
}
