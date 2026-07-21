package config

import (
    "encoding/json"
    "os"
)

type Neighbor struct {
    URL   string `json:"url"`
    Token string `json:"token"`
}

type Config struct {
    Keyfile    string     `json:"keyfile"`
	SQLip    string     `json:"sql_ip"`
    SQLpass  string     `json:"sql_auth"`
	ApiToken     string     `json:"api_token"`
	Apiport     string     `json:"api_port"`
	LogLevel string      `json:"log_level"`
	Metaon    bool      `json:"meta_on"`
	Listen    string     `json:"listen"`
	Ntp    string     `json:"ntp"`
	Socks5    string     `json:"socks5"`
	Dbfile string     `json:"db_file"`
	DbAddr string     `json:"db_addr"`
	DbPass string     `json:"db_pass"`
	VecAddr string     `json:"vec_addr"`
	VecPass string     `json:"vec_pass"`
	Permfile string   `json:"perm_file"`
	Metaofffile string   `json:"metaoff_file"`
	SkipSSLchk bool `json:"skip_ssl_check"`
	TrustCFIP bool `json:"trust_cfip"`
	TrustFor string `json:"trust_forwarded"`
    Neighbors []Neighbor `json:"neighbors"`
}

func Resolv(filename string) (Config,error) {
	var cfg Config
    data, err := os.ReadFile(filename)
    if err != nil {
        return cfg,err
    }
    err = json.Unmarshal(data, &cfg)
    if err != nil {
        return cfg,err
    }
    return cfg,nil
}