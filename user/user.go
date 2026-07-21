package user

import (
    "encoding/json"
	"encoding/hex"
	"strings"
    "net/http"
	"sync"
	"time"
	"hash/fnv"
	"encoding/base32"
	"encoding/base64"
	"kepweb-multi/sql"
	"github.com/stalltrix/kep-demo/logger"
	"crypto/sha256"
	"golang.org/x/time/rate"
	"strconv"
)

type UserInfo struct {
    UserID  string
	ID int
	Name string
	Nonce string
	Is_admin bool
	Sess *time.Timer
}

type userData struct {
    Name     string `json:"name"`
    Domain    string `json:"domain"`
	MainKeyTXT string `json:"mainkey"`
	PkeyDes string `json:"des"`
	Verified bool `json:"verified"`
    CSRF     string `json:"csrf"`
}

type cacheitem struct {
    value    *userData
    expireAt int64
}

type tokenLimiter struct {
    limiter   *rate.Limiter
    lastUsed  int64
}

var (
	dashPage []byte
	tm sync.Map
	limiterMap sync.Map
	logInfo logger.Log_TYPE
)

const maxSize = 1 << 12 //4k

func startLimiterCleaner() {
        ticker := time.NewTicker(10 * time.Minute)
        defer ticker.Stop()
        for range ticker.C {
            now := time.Now().Unix()
            limiterMap.Range(func(key, value interface{}) bool {
                tl := value.(*tokenLimiter)
                if now-tl.lastUsed > 7200 {
                    limiterMap.Delete(key)
                }
                return true
            })
        }
}

func getLimiter(userID string) *rate.Limiter {
    now := time.Now().Unix()

    if v, ok := limiterMap.Load(userID); ok {
        tl := v.(*tokenLimiter)
        tl.lastUsed = now
        return tl.limiter
    }

    tl := &tokenLimiter{
        limiter:  rate.NewLimiter(rate.Every(time.Minute/10), 10),
        lastUsed: now,
    }

    actual, _ := limiterMap.LoadOrStore(userID, tl)
    return actual.(*tokenLimiter).limiter
}

func LoadPage(pageData []byte) {
	dashPage=pageData
}

func init(){
	logInfo.SetLevel("info")
	logDebug.SetLevel("debug")
	go startGC()
	go startLimiterCleaner()
}

func startGC() {
	ticker := time.NewTicker(120 * time.Minute)
    defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()-600
		tm.Range(func(key, value interface{}) bool {
			it := value.(cacheitem)
			if now > it.expireAt {
				tm.Delete(key)
			}
			return true
		})
	}
}


func tmSet(key int, val *userData, ttl time.Duration){
    expireAt := time.Now().Add(ttl).Unix()
    tm.Store(key, cacheitem{
        value:    val,
        expireAt: expireAt,
    })
}

func tmGet(key int) (*userData, bool) {
    v, ok := tm.Load(key)
    if !ok {
        return nil, false
    }
    it := v.(cacheitem)
    if time.Now().Unix() > it.expireAt {
        tm.Delete(key)
        return nil, false
    }
    return it.value, true
}

func getUserData(uinfo *UserInfo) *userData {
	v, ok := tmGet(uinfo.ID)
    if ok {
        return v
    }
	nowUser:=&userData{
		Name: uinfo.UserID,
		Domain: uinfo.Name,
		CSRF: uinfo.Nonce+"_"+uinfo.Name,
	}
	tmSet(uinfo.ID,nowUser,180*time.Second)
	
	is_verified:=sql.GetByID("verified",uinfo.ID)
	if is_verified=="1"||is_verified=="true"{
		nowUser.Verified=true
	}
	
	mainKey_base64:=sql.GetByID("main_key",uinfo.ID)
	pub_base64:=sql.GetByID("pub_key",uinfo.ID)
	
	mainPub,err:=base64.StdEncoding.DecodeString(mainKey_base64)
	if err!=nil{
		logDebug.Println("decode mainkey err:",err)
		return nowUser
	}
	if len(mainPub) != 32 {
		logDebug.Println("mainkey len err: !32")
		return nowUser
	}
	
	nowUser.MainKeyTXT=strings.ReplaceAll(base32.StdEncoding.EncodeToString(mainPub), "=", "")

	
	pub,err:=base64.StdEncoding.DecodeString(pub_base64)
	if err!=nil{
		logDebug.Println("decode pkey err:",err)
		return nowUser
	}
	if len(pub) != 32 {
		logDebug.Println("pkey len err: !32")
		return nowUser
	}
	
	h := fnv.New64a()
	h.Write(pub)
	nowUser.PkeyDes=strconv.FormatUint(h.Sum64(), 16)
	
	return nowUser
}

func DashHandler(w http.ResponseWriter, r *http.Request,uinfo *UserInfo) {
	if uinfo.UserID==""{
		w.WriteHeader(404)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(dashPage)
}

func InfoHandler(w http.ResponseWriter, r *http.Request,uinfo *UserInfo) {
    if r.Method != http.MethodGet {
        w.WriteHeader(405)
        return
    }
	
	nowUser:=getUserData(uinfo)

    w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nowUser)
}

func PasswdHandler(w http.ResponseWriter, r *http.Request,uinfo *UserInfo) {
	if r.Method != http.MethodPost {
        w.WriteHeader(404)
        return
    }
	
	limiter := getLimiter(uinfo.UserID)
    if !limiter.Allow() {
        logInfo.Println("user: too many requests:", uinfo.UserID)
        w.WriteHeader(429)
		w.Write([]byte(`{"state":"too many requests"}`))
		return
    }
	
	nowUser:=getUserData(uinfo)

    var req struct {
        Old  string `json:"old"`
        New  string `json:"new"`
        CSRF string `json:"csrf"`
    }
	
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        writeJSON(w,http.StatusBadRequest,"invalid json")
        return
    }

    if req.CSRF != nowUser.CSRF {
        writeJSON(w, http.StatusBadRequest, "invalid csrf")
        return
    }
	
	SQL_hash:=sql.GetByID("passwd",uinfo.ID)
	hash1:=sha256.Sum256([]byte(req.Old))
	
	pwd_hash := hex.EncodeToString(hash1[:])

    if SQL_hash!=pwd_hash {
        writeJSON(w, http.StatusBadRequest, "old password incorrect")
        return
    }

    hash2:=sha256.Sum256([]byte(req.New))
	
	new_passwd := hex.EncodeToString(hash2[:])
	
	err=sql.Set("passwd",new_passwd,uinfo.ID)
	if err!=nil{
		logInfo.Println("update user password err:",err)
		writeJSON(w,500,"update password err")
		return
	}
	
    writeJSON(w, http.StatusOK, "password updated")
}

func DomainHandler(w http.ResponseWriter, r *http.Request,uinfo *UserInfo) {
    if r.Method != http.MethodPost {
        w.WriteHeader(404)
        return
    }
	
	limiter := getLimiter(uinfo.UserID)
    if !limiter.Allow() {
        logInfo.Println("user: too many requests:", uinfo.UserID)
        w.WriteHeader(429)
		w.Write([]byte(`{"state":"too many requests"}`))
		return
    }
	
	nowUser:=getUserData(uinfo)

    var req struct {
        Pass  string `json:"pass"`
        Domain string `json:"domain"`
        CSRF  string `json:"csrf"`
    }
	
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        writeJSON(w,http.StatusBadRequest,"invalid json")
        return
    }

    if req.CSRF != nowUser.CSRF {
        writeJSON(w, http.StatusBadRequest, "invalid csrf")
        return
    }
	
	SQL_hash:=sql.GetByID("passwd",uinfo.ID)
	hash1:=sha256.Sum256([]byte(req.Pass))
	
	pwd_hash := hex.EncodeToString(hash1[:])

    if SQL_hash!=pwd_hash {
        writeJSON(w, http.StatusBadRequest, "password incorrect")
        return
    }
	nowUser.Verified=false
	err=sql.Set("verified",false,uinfo.ID)
	if err!=nil{
		logInfo.Println("update user domain verified err:",err)
		writeJSON(w,500,"update domain err")
		return
	}
	if len(req.Domain)>255 {
		writeJSON(w, http.StatusBadRequest, "domain to long")
        return
	}
	for i:=0; i<len(req.Domain);i++ {
        c := req.Domain[i]
        if (c >='a'&&c<='z')||(c >= '0'&&c<= '9')||c=='.'||c=='-'{continue;}
		writeJSON(w, http.StatusBadRequest, "invalid domain")
        return
    }
	if len(req.Domain)>2{
		if req.Domain[len(req.Domain)-1]=='.'||req.Domain[0]=='.'{
			writeJSON(w, http.StatusBadRequest, "invalid domain")
			return
		}
	} else {
		writeJSON(w, http.StatusBadRequest, "invalid domain")
		return
	}
	err=sql.Set("domain",req.Domain,uinfo.ID)
	if err!=nil{
		logInfo.Println("update user domain err:",err)
		writeJSON(w,500,"update domain err")
		return
	}
	nowUser.Domain = req.Domain

    writeJSON(w, http.StatusOK, "domain updated")
}
func VerifyHandler(w http.ResponseWriter, r *http.Request,uinfo *UserInfo) {
    if r.Method != http.MethodPost {
        w.WriteHeader(404)
        return
    }
	
	limiter := getLimiter(uinfo.UserID)
    if !limiter.Allow() {
        logInfo.Println("user: too many requests:", uinfo.UserID)
        w.WriteHeader(429)
		w.Write([]byte(`{"state":"too many requests"}`))
		return
    }
	
	nowUser:=getUserData(uinfo)

    var req struct {
        CSRF  string `json:"csrf"`
    }
	
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        writeJSON(w,http.StatusBadRequest,"invalid json")
        return
    }

    if req.CSRF != nowUser.CSRF {
        writeJSON(w, http.StatusBadRequest, "invalid csrf")
        return
    }
	
	if CheckVerify(nowUser.Domain,nowUser.MainKeyTXT,nowUser.PkeyDes){
		err=sql.Set("verified",true,uinfo.ID)
		if err!=nil{
			logInfo.Println("check user domain verified err:",err)
			writeJSON(w,500,"check domain err")
			return
		}
		nowUser.Verified = true
		writeJSON(w, http.StatusOK, "verified")
	} else {
		writeJSON(w, 401, "domain verify fail")
	}
}

func writeJSON(w http.ResponseWriter,statecode int, msg string) {
    w.Header().Set("Content-Type", "application/json")
	if statecode >=100 && statecode < 600 {
		w.WriteHeader(statecode)
	}

    b,_:= json.Marshal(struct {
        State string `json:"state"`
    }{
        State: msg,
    })
	w.Write(b)
}