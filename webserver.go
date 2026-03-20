package main

import (
    "encoding/json"
    "log"
    "net/http"
    "strconv"
    "strings"
    "sync"
	"os"
	"github.com/stalltrix/kepweb/kepdb"
	"github.com/stalltrix/kep-demo/kepresolv"
	"github.com/stalltrix/kep-demo/send"
	"github.com/stalltrix/kep-demo/ntp"
	"crypto/rand"
	"encoding/hex"
	"time"
	"bytes"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/binary"
	"kepweb-multi/config"
	"io/fs"
	"embed"
	"golang.org/x/time/rate"
	"io"
	"net/url"
	"github.com/stalltrix/kep-cli/keygen"
	"html/template"
)

type Reply struct {
    ID   int    `json:"id"`
    User string `json:"user"`
    Meta string `json:"meta"`
    Me   bool   `json:"me"`
    Post string `json:"post"`
    Time int64  `json:"-"`
	Tag  uint16  `json:"tag"`
	Hex string  `json:"hex"`
}

type Post struct {
    PostHex  string
    TagID    uint16
    Owner    string
    Replies  []Reply
    LastTime int64
	TypeID byte
}

type PostIndexView struct {
    Own      string `json:"own"`
    Lasttime string `json:"lasttime"`
    Reply    int    `json:"reply"`
    Lastview string `json:"lastview"`
	Hex      string `json:"hex"`
	Tag      uint16 `json:"tag"`
}

type ReplyRequest struct {
    PostPayload string `json:"post_payload"`
	Tag int  `json:"tag"`
	Point_to string  `json:"point_to"`
	TypeID int  `json:"typeid"`
}

type LoginType struct {
    Token   string    `json:"token"`
}

type indexCache struct {
    Txt []byte
	Last int64
}

type map向量 struct {
    x string
	y int
}

type tokenLimiter struct {
    limiter   *rate.Limiter
    lastUsed  int64
}

type UserInfo struct {
    Name  string
	Is_admin bool
}

var (
    postStore = make(map[string]*Post)
	fileIndex []byte
	fileNewPost []byte
	allLook   sync.RWMutex
	sessMap sync.Map
	myself string
	nextroute []send.NextMsg
	mainPub,mainPriv []byte
	nonceMap sync.Map 
	maxMarkdownSize = 60 * 1024
	Idxcache indexCache 
	token_UrlApi string
	token_urlPort string
	sortList [65536]string
	sortIdx uint16
	二维指针 sync.Map
	limiterMap sync.Map
	neighborTokenMap sync.Map
	manager_csrf string
	manager_tmpl *template.Template
	will_change_reply map[string]Reply
	top_post PostIndexView //置顶帖子
	userInfo = make(map[string]UserInfo)
	userLock sync.RWMutex
	keyfile string
)

//go:embed static/*
var staticFiles embed.FS

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

func getLimiter(ipaddr string) *rate.Limiter {
    now := time.Now().Unix()

    if v, ok := limiterMap.Load(ipaddr); ok {
        tl := v.(*tokenLimiter)
        tl.lastUsed = now
        return tl.limiter
    }

    tl := &tokenLimiter{
        limiter:  rate.NewLimiter(rate.Every(time.Minute/30), 30),
        lastUsed: now,
    }

    actual, _ := limiterMap.LoadOrStore(ipaddr, tl)
    return actual.(*tokenLimiter).limiter
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
    // /view/{tag_id}/{post_hex}
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) != 3 {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
	
	is_login := false
	var uinfo *UserInfo
	cookie, err := r.Cookie("seesion")
	if err == nil {
		if cookie.Value != "" {
			var val interface{}
			val,is_login=sessMap.Load(cookie.Value)
			if is_login {
				uinfo=val.(*UserInfo)
			}
		}
	}

    postHex := parts[2]
	
	allLook.RLock()
    post, ok := postStore[postHex]
	allLook.RUnlock()
	
    if !ok {
        http.Error(w, "post not found", http.StatusNotFound)
        return
    }
	
	if !is_login {
		if post.TypeID != 0 {
			http.Error(w, "post not found", http.StatusNotFound)
			return
		}
	}
	
	if http.MethodPost==r.Method{
		if !is_login {
			http.Error(w, "not suppered", http.StatusBadRequest)
			return
		}
		var req ReplyRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "not suppered", http.StatusBadRequest)
            return
        }
		hash,_:=async_send(req,uinfo)
		
		replyID:=len(post.Replies)+1
		allLook.Lock()
		reply := Reply{
            ID:   replyID,
            User: uinfo.Name,
            Meta: "",
            Me:   post.Owner==uinfo.Name,
            Post: req.PostPayload,
            Time: time.Now().Unix(),
			Tag: uint16(req.Tag),
			Hex: hash,
        }
		post.Replies = append(post.Replies, reply)
        post.LastTime = reply.Time
		allLook.Unlock()
		newV:=&map向量{
			x: post.Replies[0].Hex,
			y: replyID-1,
		}
		二维指针.Store(hash,newV)
		sortList[sortIdx]=post.Replies[0].Hex
		sortIdx++
		
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
		return
	}
	json.NewEncoder(w).Encode(post.Replies)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
    // /index/{tag_id}/{page_idx}
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) != 3 {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    tagID := parts[1]
    pageIdx, err := strconv.Atoi(parts[2])
    if err != nil || pageIdx < 1 {
        http.Error(w, "invalid page", http.StatusBadRequest)
        return
    }
	
	is_login := false
	cookie, err := r.Cookie("seesion")
	if err == nil {
		if cookie.Value != "" {
			_,is_login=sessMap.Load(cookie.Value)
		}
	}
	
	if !is_login {
		now:=int64(time.Now().Unix())
		if Idxcache.Last +90 > now {
			w.Header().Set("Content-Type", "application/json")
			w.Write(Idxcache.Txt)
			return
		}
	}
	
	var posts []*Post
	{
	diff :=make(map[string]bool)
	allLook.RLock()
	i:=sortIdx
	for j:=0;j<2048;j++{
		i--
		if tagID == "all" {
			hex:=sortList[i]
			if hex == "" {
				break
			}
			_,ok:=diff[hex]
			if ok {
				continue
			}
			post, ok := postStore[hex]
			if ok {
				diff[hex]=false
				posts = append(posts, post)
			}
		} else {
			hex:=sortList[i]
			if hex == "" {
				break
			}
			_,ok:=diff[hex]
			if ok {
				continue
			}
			tag,err:=strconv.Atoi(tagID)
			if err !=nil {
				continue
			}
			post, ok := postStore[hex]
			if ok {
				if int(post.TagID)==tag {
					diff[hex]=false
					posts = append(posts, post)
				}
			}
		}
	}
	allLook.RUnlock()
	}

    start := (pageIdx - 1) * 16
    end := start + 16
    if start >= len(posts) {
        w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
        return
    }
    if end > len(posts) {
        end = len(posts)
    }

    var resp []PostIndexView
	if pageIdx==1 {
		if top_post.Hex != "" {
			resp = append(resp, top_post)
		}
	}
    for _, p := range posts[start:end] {
        lastView := ""
        if len(p.Replies) > 0 {
			line := strings.SplitN(p.Replies[0].Post, "\n", 2)[0]
            lastView = strings.TrimPrefix(line, "# ")
        }
        resp = append(resp, PostIndexView{
            Own:      p.Owner,
            Lasttime: strconv.FormatInt(p.Replies[len(p.Replies)-1].Time, 10),
            Reply:    len(p.Replies),
            Lastview: lastView,
			Hex: p.PostHex,
			Tag: p.TagID,
        })
    }
	
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(resp)
	if err != nil {
		w.Write([]byte(`{"status":0}`))
		return
	}
	Idxcache.Txt=b
	Idxcache.Last=time.Now().Unix()
	w.Write(b)
}

func async_send(payload ReplyRequest,uinfo *UserInfo) (string,error) {
	var err error
	var priv,signKey,pub []byte
	pub, err = os.ReadFile(keyfile+"/"+uinfo.Name+".pub")
    if err != nil {
	   return "",err
    }
	
    priv, err = os.ReadFile(keyfile+"/"+uinfo.Name+".priv")
    if err != nil {
        return "",err
    }

    signKey, err = os.ReadFile(keyfile+"/"+uinfo.Name+".sig")
    if err != nil {
       return "",err
    }
    version := byte(1)
    hashtype := byte(1)
    typeID := byte(payload.TypeID & 255)
    tag := uint16(payload.Tag & 65535)
    tag2 := tag
    ttl := byte(128)
    compressType := byte(0)

    domain := []byte(uinfo.Name)
    txt := []byte(payload.PostPayload)
    
	var pointTo []byte
	
	if len(payload.Point_to) < 4 {
		pointTo = []byte{} // 发帖，无指针
	} else {
		bytes, err := hex.DecodeString(payload.Point_to)
		if err != nil {
			log.Println("send reply err:",err)
			return "",err
		}
		pointTo = bytes
	}
	
    buf := new(bytes.Buffer)

    buf.WriteByte(version)
    buf.WriteByte(hashtype)
    buf.WriteByte(byte(len(domain)))
    buf.Write(unix40()[:])

    binary.Write(buf, binary.BigEndian, uint16(len(txt)))

    buf.Write(mainPub)
    buf.Write(pub)
    buf.Write(signKey)

    buf.WriteByte(typeID)
    buf.WriteByte(byte(len(pointTo)))
    binary.Write(buf, binary.BigEndian, tag)
    buf.WriteByte(compressType)

    buf.Write(domain)
    buf.Write(pointTo)
    buf.Write(txt)

    h := sha256.Sum256(buf.Bytes())
    tHash := h[:]
    buf.Write(tHash)

    signature := ed25519.Sign(priv, tHash)
    buf.Write(signature)

    binary.Write(buf, binary.BigEndian, tag2)
    buf.WriteByte(ttl)

    msg := buf.Bytes()
	hashHex := hex.EncodeToString(tHash)
	go func(){
	err = send.Nextmsg(msg,"")
	if err != nil {
		log.Println("send msg err:",err)
	}
	}()
	return hashHex,nil
}

func loadData(tag string,renew bool){
		hexs,err:=kepdb.ReadHash(tag)
			if err ==nil {
			txt,domain,timestamp,point_to,perm,key_des,_,tag_i,_,err:=kepresolv.Resolv(hexs)
			if err !=nil {
				log.Println("load data err:",err)
				return;
			}
			if point_to != nil {
				//回帖子内容，跳过
				if !renew{
					//log.Println("回帖子内容，跳过")
				} else {
					o_hex:=hex.EncodeToString(point_to)
					o_hexs,err:=kepdb.ReadHash(o_hex)
					if err!=nil {
						log.Println("ERR: 找不到原始帖子",err)
						return
					}
					_,o_domain,_,_,_,o_key_des,_,o_tag_i,_,err:=kepresolv.Resolv(o_hexs)
					if err!=nil {
						log.Println("ERR: 原始帖子err",err)
						return
					}
					val,ok:=二维指针.Load(o_hex)
					if !ok {
						log.Println("drop wild point hex:",o_hex)
						return;
					}
					nowV:=val.(*map向量)
					allLook.RLock()
					o_post,ok:=postStore[nowV.x]
					allLook.RUnlock()
				if ok {
					if tag_i == 65534 {
						if nowV.y == 0 {
						if (key_des == o_key_des) && bytes.Equal(domain,o_domain){
						if timestamp > o_post.Replies[0].Time{
							o_post.TypeID=byte(perm & 255)
							o_post.Replies[0]=Reply{ID: 1, User: string(domain), Meta: "", Me: false, Post: string(txt), Time: timestamp, Tag: o_tag_i, Hex: o_hex}
						}}}else {
							if len(o_post.Replies)>nowV.y{
								o_post.Replies[nowV.y]=Reply{ID: nowV.y+1, User: string(domain), Meta: "", Me: false, Post: string(txt), Time: timestamp, Tag: o_tag_i, Hex: o_hex}
							}
						}
						return
					}
						lastID:=len(o_post.Replies)
						o_post.Replies = append(o_post.Replies, Reply{
    ID:   lastID,
    User: string(domain),
    Meta: "",
    Me:   (key_des == o_key_des) && bytes.Equal(domain,o_domain),
    Post: string(txt),
    Time: timestamp,
	Tag: tag_i,
	Hex: tag,
 })
 	newV:=&map向量{
		x: o_hex,
		y: lastID,
	}
	lastID++
	二维指针.Store(tag,newV)
	sortList[sortIdx]=o_hex
	sortIdx++
				}
				}
				return;
			}
			var newRly = []Reply{{ID: 1, User: string(domain), Meta: "", Me: true, Post: string(txt), Time: timestamp, Tag: tag_i, Hex: tag},}
			var lastID=2
			subs,err:=kepdb.ReadSub(tag)
			if err ==nil {
for _,sub := range subs {
	hex_byte,err:=kepdb.ReadHash(sub)
	if err ==nil {
 txt2,domain2,timestamp2,point_to2,perm2,key_des2,_,tagi2,_,err:=kepresolv.Resolv(hex_byte)
 if err !=nil {
	log.Println("load data err:",err)
	continue;
	}
	if tagi2 == 65534 {
		o_hex2:=hex.EncodeToString(point_to2)
		if o_hex2 == tag {
		if (key_des == key_des2) && bytes.Equal(domain,domain2) {
			//本人
			if timestamp2 > newRly[0].Time{
			newRly[0]=Reply{
    ID:   1,
    User: string(domain2),
    Meta: "",
    Me:   string(domain2)==myself,
    Post: string(txt2),
    Time: timestamp2,
	Tag: tag_i,
	Hex: tag,
			}
	perm=perm2
		}}
		}
		continue;
	}
 newRly = append(newRly, Reply{
    ID:   lastID,
    User: string(domain2),
    Meta: "",
    Me:   (key_des == key_des2) && bytes.Equal(domain,domain2),
    Post: string(txt2),
    Time: timestamp2,
	Tag: tagi2,
	Hex: sub,
 })
 	newV:=&map向量{
		x: tag,
		y: lastID-1,
	}
	二维指针.Store(sub,newV)
 lastID++
	}
}
			}
			
	allLook.Lock()
    postStore[tag] = &Post{
        PostHex: tag,
        TagID:   tag_i,
        Owner:   string(domain),
        LastTime: timestamp,
        Replies: newRly,
		TypeID: perm,
    }
	allLook.Unlock()
	newV:=&map向量{
		x: tag,
		y: 0,
	}
	二维指针.Store(tag,newV)
	sortList[sortIdx]=tag
	sortIdx++
		}
}

func initData() {
	for i:=0;i<11;i++{
		tags,err:=kepdb.ReadTag(i)
		if err ==nil {
			for _,tag := range tags {
				loadData(tag,false);}}
	}
	tags,err:=kepdb.ReadTag(65534)
	if err ==nil {
	will_change_reply=make(map[string]Reply);
	for _,tag := range tags {
	hexs,err:=kepdb.ReadHash(tag)
	if err ==nil {
	txt,domain,timestamp,point_to,_,_,_,tag_i,point_to_root,err:=kepresolv.Resolv(hexs)
			if err !=nil {
				log.Println("load data err:",err)
				continue;
			}
			if len(point_to_root)<4{
				continue;
			}
		point_to_hex:=hex.EncodeToString(point_to)
		_,ok:=will_change_reply[point_to_hex]
		if !ok {
	will_change_reply[point_to_hex]=Reply{
    ID:   0,
    User: string(domain),
    Meta: "",
    Me:   string(domain)==myself,
    Post: string(txt),
    Time: timestamp,
	Tag: tag_i,
	Hex: point_to_hex,
	}
	}}}
	for k,v:=range will_change_reply {
		val,ok:=二维指针.Load(k)
		if ok {
			nowV:=val.(*map向量)
	allLook.RLock()
    post,ok:=postStore[nowV.x]
	allLook.RUnlock()
	if ok {
		if len(post.Replies)>nowV.y{
			if post.Replies[nowV.y].Time < v.Time {
			v.ID=nowV.y+1
			post.Replies[nowV.y]=v
			}
		}
	}
		}else{
			log.Println("debug: post not found",k)
		}
	}
	will_change_reply=nil
	}
}


func auto_renew_data(){
for {
	time.Sleep(time.Second * 30)
	newData:=renewData()
	if newData !=nil {
		for _,tag := range newData {
			log.Println("debug: access msg:",tag)
			loadData(tag,true)
		}
	}
}
}

func renewData() []string {
	nodeUrlApi := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=msg&req=0&token="+token_UrlApi
	resp, err := http.Get(nodeUrlApi)
	if err != nil {
		log.Println("task err:",err)
		return nil
	}
	defer resp.Body.Close()
	var arr []string
	err = json.NewDecoder(resp.Body).Decode(&arr)
	if err != nil {
		log.Println("decode json err:",err)
		return nil
	}
	return arr
}

func meHandler(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cookie, err := r.Cookie("seesion")
		if err != nil {
			w.Write([]byte(`{"status":0}`))
			return
		}
		val,ok:=sessMap.Load(cookie.Value)
		if !ok {
			w.Write([]byte(`{"status":0}`))
			return
		}
		info:=val.(*UserInfo)
		
		w.Write([]byte(`{ "status":1, "user":"`+info.Name+`" }`))
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req LoginType
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.Write([]byte(`{"status":0}`))
        return
    }
	user_ip := r.Header.Get("CF-Connecting-IP")
	ipaddr := user_ip
	if len(user_ip) > 19 {
		ipaddr=user_ip[:19]
	}
	limiter := getLimiter(ipaddr)
    if !limiter.Allow() {
        log.Println("WARN: Rate limit exceeded ,ip:", user_ip)
        w.Write([]byte(`{"status":0}`))
		return
    }
	userLock.RLock()
	info,ok:=userInfo[req.Token]
	userLock.RUnlock()
	if !ok {
		w.Write([]byte(`{"status":0}`))
        return
	}
	sess,err:=randSess(32)
	if err !=nil {
		log.Println(err)
		w.Write([]byte(`{"status":0}`))
        return
	}
	
	cookie := &http.Cookie{
    Name:     "seesion",
    Value:    sess,
    Path:     "/",
    MaxAge:   3600*24*15,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
	}
    http.SetCookie(w, cookie)

	sessMap.Store(sess,&info)
	time.AfterFunc(3600*24*15*time.Second, func() {
		sessMap.Delete(sess)
	})
	w.Write([]byte(`{"status":1,"user":"`+info.Name+`","img":"https://i.pravatar.cc/100"}`))
}

func main() {
	argc:=len(os.Args)
	if argc <=1 {
		log.Println("usage:")
		log.Println("\twebserver [config.json] [logfile]")
		return
	}
	cfg_file:=os.Args[1]
	var err error
	
	fileNewPost,err=os.ReadFile("markdown.html")
	if err!=nil {
		log.Fatalln("can't read markdown.html",err)
	}
	
	manager_tmpl,err=template.ParseFiles("manager.html")
	if err!=nil {
		log.Fatalln("can't read manager.html",err)
	}
	
	cfg,err := config.Resolv(cfg_file)
	if err!=nil {
		log.Fatalln("can't read config.json",err)
	}
	
	fileIndex,err=os.ReadFile("ui.html")
	if err!=nil {
		log.Fatalln("can't read ui.html",err)
	}
	
	if cfg.Keyfile=="" {
		log.Fatal("Err: keyfile is null")
	}
	if len(cfg.ApiToken) < 8 {
		log.Fatal("Err: token is null")
	}
	myself = cfg.Domain
	token_UrlApi=cfg.ApiToken
	
	if myself == "" {
		log.Fatal("Err: myself is null")
	}
	
	nextroute=make([]send.NextMsg,len(cfg.Neighbors))
	for i:= range nextroute {
		nextroute[i].Addr=cfg.Neighbors[i].URL
		nextroute[i].Auth=cfg.Neighbors[i].Token
	}
	
	send.Send_Init(nextroute,"")
	
	if cfg.Ntp != "" {
		ntp.Ntp_Init(cfg.Ntp)
		log.Println("start ntp client:",cfg.Ntp)
	}
	
    mainPub, err = os.ReadFile(cfg.MainKey)
    if err != nil {
       log.Fatal("Err: read user key err:",err)
    }
	mainPriv, err = os.ReadFile(cfg.Mainpriv)
	if err != nil {
		log.Fatal("Err: read user priv err:",err)
	}
	
	keyfile = cfg.Keyfile
	
	err = loadUserInfo("userinfo.json")
	if err!=nil{
		log.Fatal("Err: read userinfo err:",err)
	}
	
	initData()
	
    http.HandleFunc("/view/", viewHandler)
    http.HandleFunc("/index/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/me", meHandler)
	http.HandleFunc("/index.php", indexpage)
	http.HandleFunc("/t/topic/", indexpage)
	http.HandleFunc("/manager", managerHandler)
	
	staticFS, _ := fs.Sub(staticFiles, "static")

    http.Handle("/static/",
        http.StripPrefix("/static/",
            http.FileServer(http.FS(staticFS)),
        ),
    )
	
	if cfg.Listen == "" {
		log.Fatal("Err: listen addr is null:")
		return
	}
	
	token_urlPort = cfg.Apiport
	
	if token_urlPort == "" {
		token_urlPort="10428"
	}

    log.Println("server started on: ",cfg.Listen)
	if argc >2 {
	logfile:=os.Args[2]
	logpath,err :=os.OpenFile(logfile,os.O_WRONLY|os.O_CREATE|os.O_APPEND,0644)
	if err != nil {
		log.Println(err)
		return
	}
	log.SetOutput(logpath)
	}
	go auto_renew_data();
	go auto_renew_csrf();
    log.Fatal(http.ListenAndServe(cfg.Listen, nil))
}

func managerHandler(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(403)
            w.Write([]byte("access deny"))
			return
		}
		
		cookie, err := r.Cookie("seesion")
        if err != nil {
            w.WriteHeader(403)
            w.Write([]byte("access deny"))
            return
        }

        val, ok := sessMap.Load(cookie.Value)
        if !ok {
            w.WriteHeader(403)
            w.Write([]byte("access deny"))
            return
        }
		
		info:=val.(*UserInfo)
		
		if !info.Is_admin {
			w.WriteHeader(403)
            w.Write([]byte("access deny"))
            return
		}
		
	type User struct {
		Req string `json:"req"`
		Act string `json:"act"`
		Csrf string `json:"csrf"`
		Url string `json:"url"`
	}
	
	var user User
    err = json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
		if user.Csrf != manager_csrf{
			http.Error(w, "csrf token err", http.StatusBadRequest)
			return
		}
		req := user.Req
		act := user.Act
		Ner_url:=user.Url
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if req == "" || act == "" {
			io.WriteString(w,`{"state":"not found"}`)
			return
		}
		
switch req {
case "list":{

    url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=neighbor&req=list&key=123456789&token="+token_UrlApi

    resp, err := http.Get(url)
    if err != nil {
        io.WriteString(w,`{"state":"`+err.Error()+`"}`)
        return
    }

    body, err := io.ReadAll(resp.Body)
    resp.Body.Close()

    if err != nil {
        io.WriteString(w,`{"state":"`+err.Error()+`"}`)
        return
    }

    type ApiResp struct{
        State string   `json:"state"`
        Data  []string `json:"data"`
    }

    var api ApiResp
	
	//log.Println("debug: list=",string(body))

    err = json.Unmarshal(body,&api)
    if err != nil {
        io.WriteString(w,`{"state":"`+err.Error()+`"}`)
        return
    }

    result := make([]string,0,len(api.Data))

    for _,realKey := range api.Data {

        token := genPanelToken(realKey)

        neighborTokenMap.Store(token,realKey)

        result = append(result,token)
    }

    out := struct{
        State string   `json:"state"`
        Data  []string `json:"data"`
    }{
        State:"OK",
        Data:result,
    }

    w.Header().Set("Content-Type","application/json")
    json.NewEncoder(w).Encode(out)
}
case "ban":{
	if strings.Contains(act, ":") {
	if strings.HasSuffix(act, myself) {
		userLock.Lock()
		_,ok:=userInfo[act]
		if ok {delete(userInfo,act);}
		userLock.Unlock()
		if ok {
			io.WriteString(w,`{"state":"OK"}`)
		} else {
			io.WriteString(w,`{"state":"not found"}`)
		}
	}else{
		io.WriteString(w,`{"state":"req err, need user:pass"}`)
	}
	return
	}
	url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=ban&req="+url.QueryEscape(act)+"&token="+token_UrlApi
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w,`{"state":"`+err.Error()+`"}`)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	io.WriteString(w,`{"state":"OK"}`)
}
case "unban":{
	if strings.Contains(act, ":") {
	if strings.HasSuffix(act, myself) {
		p := strings.Split(act, ":")
		if len(p[0])<1{
			io.WriteString(w,`{"state":"username too short"}`)
			return
		}
		userLock.Lock()
		_,ok:=userInfo[act]
		if !ok {
				userInfo[act]=UserInfo{
					Name: p[0],
					Is_admin: false,
				}
		}
		userLock.Unlock()
		if !ok {
			pub, priv, err:=keygen.Gen_pkey()
			if err!=nil{
				io.WriteString(w,`{"state":"`+err.Error()+`"}`)
				return
			}
			signKey:=keygen.Sig_pkey(pub, mainPriv)
			os.WriteFile(keyfile+"/"+p[0]+".pub", pub, 0600);
			os.WriteFile(keyfile+"/"+p[0]+".priv", priv, 0600);
			os.WriteFile(keyfile+"/"+p[0]+".sig", signKey, 0600);
			io.WriteString(w,`{"state":"OK"}`)
		} else {
			io.WriteString(w,`{"state":"user exist"}`)
		}
	}else{
		io.WriteString(w,`{"state":"req err, need user:pass"}`)
	}
	return
	}
	url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=unban&req="+url.QueryEscape(act)+"&token="+token_UrlApi
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w,`{"state":"`+err.Error()+`"}`)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	io.WriteString(w,`{"state":"OK"}`)
}
case "pmsg":{
	//私信
	//TODO:
	io.WriteString(w,`{"state":"TODO..."}`)
}
case "top":{
	//置顶
	allLook.RLock()
	post_top,ok:=postStore[act]
	allLook.RUnlock()
	if !ok {
		io.WriteString(w,`{"state":"set-top: post not found"}`)
		return
	}
	line := strings.SplitN(post_top.Replies[0].Post, "\n", 2)[0]
    lastView := strings.TrimPrefix(line, "# ")
	top_post=PostIndexView{
            Own:      post_top.Owner,
            Lasttime: strconv.FormatInt(post_top.Replies[len(post_top.Replies)-1].Time, 10),
            Reply:    len(post_top.Replies),
            Lastview: lastView,
			Hex: post_top.PostHex,
			Tag: post_top.TagID,
        }
	io.WriteString(w,`{"state":"set-top: OK"}`)
}
case "delmsg":{
	del_ok:=false
	val,ok:=二维指针.Load(act)
	if ok {
		nowV:=val.(*map向量)
		if nowV.y==0{
	allLook.Lock()
    _,ok=postStore[nowV.x]
	if ok {delete(postStore,nowV.x);del_ok=true;}
	allLook.Unlock()
		}else{
	allLook.RLock()
    post,ok:=postStore[nowV.x]
	allLook.RUnlock()
	if ok {
		del_ok=true;
		if len(post.Replies)>nowV.y{
			post.Replies[nowV.y].Post="[user delete]"
		}
		path,err:=kepdb.FindALLFile(act + ".mdb")
		if err!=nil {
			log.Println("del post err:",err)
		}else{
			os.Remove(path)
		}
	}
		}
		
		if del_ok {
		io.WriteString(w,`{"state":"del post OK"}`)
		} else {
			io.WriteString(w,`{"state":"del post not found"}`)
		}
	}else{
		io.WriteString(w,`{"state":"del post not found"}`)
	}
}
case "add_neighbor":{
	if len(Ner_url) <4 {
		io.WriteString(w,`{"state":"neighbor url is null"}`)
		return
	}
	if !strings.HasPrefix(Ner_url, "http") {
		io.WriteString(w,`{"state":"neighbor url not start with http?://"}`)
		return
	}
	url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=neighbor&req=set&key="+url.QueryEscape(act)+"&token="+token_UrlApi+"&url="+url.QueryEscape(Ner_url)
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w,`{"state":"`+err.Error()+`"}`)
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		io.WriteString(w,`{"state":"`+err.Error()+`"}`)
		return
	}
	io.WriteString(w,`{"state":"`+string(body)+`"}`)
}
case "del_neighbor":{

    v,ok := neighborTokenMap.Load(act)

    if !ok{
        io.WriteString(w,`{"state":"token not found"}`)
        return
    }

    realKey := v.(string)

    url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=neighbor&req=del&key="+url.QueryEscape(realKey)+"&token="+token_UrlApi
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w,`{"state":"`+err.Error()+`"}`)
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		io.WriteString(w,`{"state":"`+err.Error()+`"}`)
		return
	}
	io.WriteString(w,`{"state":"`+string(body)+`"}`)
}
default:{
    io.WriteString(w,`{"state":"not found"}`)
}}
}

func indexpage(w http.ResponseWriter, r *http.Request) {

    query := r.URL.Query()
    manager := query.Get("manager")

    if manager != "" || r.Method == http.MethodPost {

        cookie, err := r.Cookie("seesion")
        if err != nil {
            w.WriteHeader(403)
            w.Write([]byte("access deny"))
            return
        }

        val, ok := sessMap.Load(cookie.Value)
        if !ok {
            w.WriteHeader(403)
            w.Write([]byte("access deny"))
            return
        }
		info:=val.(*UserInfo)

        if r.Method == http.MethodPost {

            err := r.ParseForm()
            if err != nil {
                w.WriteHeader(400)
                return
            }

            markdown := r.Form.Get("markdown")
			tag := r.Form.Get("tag")
			typeid := r.Form.Get("typeid")
            nonce := r.Form.Get("nonce")
			point_to := r.Form.Get("pointto")
			point_to_root := r.Form.Get("pointtoroot")
			
			tagn,err:=strconv.Atoi(tag)
			if err !=nil {
				w.WriteHeader(400)
				w.Write([]byte("tag is null"))
                return
			}
			
			typeidn,err:=strconv.Atoi(typeid)
			if err !=nil {
				w.WriteHeader(400)
				w.Write([]byte("typeid is null"))
                return
			}

            if markdown == "" || nonce == "" {
                w.WriteHeader(400)
				w.Write([]byte("markdown is null"))
                return
            }

            if len(markdown) > maxMarkdownSize {
                w.WriteHeader(400)
                w.Write([]byte("markdown too large"))
                return
            }

            if !addNonce(nonce) {
                w.Write([]byte("duplicate"))
                return
            }

			sendNewPost(markdown,tagn,typeidn,point_to,point_to_root,info)

            w.Write([]byte("post ok"))
            return
        }

        if manager == "newpost" {

            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.Write(fileNewPost)
            return

        } else if manager == "banuser" {
			
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
    u := struct {
		Tokenk1 string
	}{
        Tokenk1: manager_csrf,
    }
			manager_tmpl.Execute(w, u)
            return
        }

        return
    }

    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.Write(fileIndex)
}

func genPanelToken(token string) string {
	var b [2]byte
	rand.Read(b[:])
	lens:=len(token)
	if lens<3{token+="****";}
	newtoken:=token[:lens/2] + "*****"+token[lens-1:lens]+"["+strconv.Itoa(int(b[0])<<8 | int(b[1]))+"]"
    return newtoken
}

func addNonce(nonce string) bool {
    _, loaded := nonceMap.LoadOrStore(nonce, time.Now().Unix())
    if loaded {
        return false
    }
    time.AfterFunc(120*time.Second, func() {
        nonceMap.Delete(nonce)
    })
    return true
}

func sendNewPost(txt string,tag,typeid int,point_to,point_to_root string,uinfo *UserInfo){
	var req ReplyRequest
	req.PostPayload=txt
	req.Tag = tag
	req.TypeID = typeid
	req.Point_to=point_to+point_to_root
        
	hash,_:=async_send(req,uinfo)
	if hash == "" {
		return
	}
	timestamp:=int64(time.Now().Unix())
	var newRly = []Reply{{ID: 1, User: uinfo.Name, Meta: "", Me: true, Post: string(txt), Time: timestamp, Tag: uint16(req.Tag), Hex: hash},}
	
if req.Tag == 65534 {
	val,ok:=二维指针.Load(point_to)
	if !ok {
		return
	}
	NowV:=val.(*map向量)
	allLook.RLock()
	o_post,ok:=postStore[NowV.x]
	allLook.RUnlock()
	if ok {
		if NowV.y==0{
		if o_post.Owner == uinfo.Name{
		o_tag:=o_post.Replies[0].Tag
		o_post.TypeID=byte(typeid & 255)
		o_post.Replies[0]=Reply{ID: 1, User: uinfo.Name, Meta: "", Me: true, Post: string(txt), Time: timestamp, Tag: o_tag, Hex: point_to}
		}}else{
			if len(o_post.Replies)>NowV.y{
		o_tag:=o_post.Replies[NowV.y].Tag
		o_post.Replies[NowV.y]=Reply{ID: NowV.y+1, User: uinfo.Name, Meta: "", Me: true, Post: string(txt), Time: timestamp, Tag: o_tag, Hex: point_to}
			}
		}
	}
}else{
	allLook.Lock()
	postStore[hash] = &Post{
        PostHex: hash,
        TagID:   uint16(tag),
        Owner:   uinfo.Name,
        LastTime: timestamp,
        Replies: newRly,
		TypeID: byte(typeid & 255),
	}
	allLook.Unlock()
	newV:=&map向量{
		x: hash,
		y: 0,
	}
	二维指针.Store(hash,newV)
}
	sortList[sortIdx]=hash
	sortIdx++
}

func autoSave(){
for{
	time.Sleep(time.Second*300)
	err := saveUserInfo("userinfo.json")
	if err!=nil{
		log.Println("err: save user task:",err)
	}
}
}

func unix40() []byte {
    var b [5]byte
    t := uint64(ntp.Get_Now_Time())
    b[0] = byte(t >> 32)
    b[1] = byte(t >> 24)
    b[2] = byte(t >> 16)
    b[3] = byte(t >> 8)
    b[4] = byte(t)
    return b[:]
}

func auto_renew_csrf(){
	var err error
for{
	manager_csrf,err=randSess(8)
	if err!=nil{
		manager_csrf=sortList[sortIdx-1]
	}
	time.Sleep(time.Second*60*60*24)
}
}

func randSess(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    bytes := make([]byte, n)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    for i := 0; i < n; i++ {
        bytes[i] = letters[int(bytes[i])%len(letters)]
    }
    return string(bytes), nil
}

func loadUserInfo(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    err = decoder.Decode(&userInfo)
    if err != nil {
        return err
    }
	return nil
}

func saveUserInfo(filename string) error {
    file, err := os.Create(filename)
    if err != nil {
		return err
    }
    encoder := json.NewEncoder(file)
	userLock.RLock()
    err = encoder.Encode(userInfo)
	userLock.RUnlock()
	file.Close()
    if err != nil {
        return err
    }
	return nil
}