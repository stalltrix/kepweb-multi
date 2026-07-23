package config

import (
    "encoding/json"
    "os"
	"github.com/stalltrix/kep-demo/logger"
)

type Neighbor struct {
    URL   string `json:"url"`
    Token string `json:"token"`
}

type CustomData struct {
    HTTPCode    int    `json:"http-code"`
    ContentType string `json:"content-type"`
    Pages_file  string `json:"resp_file"`
}

type CaptchaSet struct {
    ServerAddr string `json:"server_url"`
    SecretKey string `json:"secret_key"`
	UA string `json:"user-agent"`
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
	StaticFile  string     `json:"static"`
	CustomIdx CustomData `json:"custom_index"`
	Custom404 string  `json:"custom_file404"`
	Captcha CaptchaSet `json:"captcha"`
}

func Resolv(filename string) (Config,error) {
	var cfg Config
    data, err := os.ReadFile(filename)
    if err != nil {
        return cfg,err
    }
    err = json.Unmarshal(data, &cfg)
    if err != nil {
		logger.Print("Warn: decode json err:"+err.Error()+",try decode with jsonc")
		err = json.Unmarshal(removejsonc(data), &cfg)
		if err != nil {
			return cfg,err
		}
		logger.Print("Warn: decode with jsonc success")
    }
    return cfg,nil
}

func removejsonc(src []byte) []byte {
    dst := make([]byte, 0, len(src))
    inString := false
    escape := false
    for i := 0; i < len(src); i++ {
        c := src[i]
        if inString {
            dst = append(dst, c)
            if escape {
                escape = false
                continue
            }
            if c == '\\' {
                escape = true
                continue
            }
            if c == '"' {
                inString = false
            }
            continue
        }
        if c == '"' {
            inString = true
            dst = append(dst, c)
            continue
        }
        if c == '/' && i+1 < len(src) && src[i+1] == '/' {
            for i < len(src) && src[i] != '\n' {
                i++
            }
            if i < len(src) {
                dst = append(dst, '\n')
            }
            continue
        }
        dst = append(dst, c)
    }
    return dst
}