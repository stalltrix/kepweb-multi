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
    MainKey   string     `json:"mainkey"`
	Mainpriv   string     `json:"mainpriv"`
    Keyfile    string     `json:"keyfile"`
    Domain    string     `json:"domain"`
	ApiToken     string     `json:"api_token"`
	Apiport     string     `json:"api_port"`
	Listen    string     `json:"listen"`
	Ntp    string     `json:"ntp"`
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