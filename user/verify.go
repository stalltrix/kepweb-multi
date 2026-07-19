package user

import (
	"sync"
	"time"
	"net"
	"github.com/stalltrix/kep-demo/logger"
)

var (
	blacklist sync.Map
	ttl = time.Second * 10
	logDebug logger.Log_TYPE
)
func CheckVerify(domain,kep,des string) bool{
	if len(domain)>2 && domain[len(domain)-1]=='.'{
		return false
	}
	if !allow(domain){
		return false
	}
	fail(domain)
	kepTXT,desTXT,err:=dnsLookup(domain)
	if err!=nil {
		logDebug.Println("nslookup fail:",err)
		return false
	}
	if kep!=kepTXT{
		return false
	}
	for _,v:=range desTXT {
		if v==des{
			return true
		}
	}
	return false
}

func dnsLookup(domain string) (string,[]string,error) {
	txtRecords, err := net.LookupTXT(domain)
    if err != nil {
        return "",nil,err
    }
	
	var kepTXT string
	var desTXT []string
	
	for _, txt := range txtRecords {
		if len(txt) >= 4 && txt[:4] == "kep=" {
			if kepTXT=="" {kepTXT=txt[4:];}
		} else if len(txt) >= 4 && txt[:4] == "des=" {
			desTXT = append(desTXT,txt[4:])
		}
    }
	return kepTXT,desTXT,nil
}

func allow(addr string) bool {
    v, ok := blacklist.Load(addr)
    if !ok {
        return true
    }

    expire := v.(time.Time)
    if time.Now().After(expire) {
        blacklist.Delete(addr)
        return true
    }

    return false
}

func fail(addr string) {
    blacklist.Store(addr, time.Now().Add(ttl))
}