package main

import (
    "encoding/json"
    "github.com/stalltrix/kep-demo/logger"
    "net/http"
    "strconv"
    "strings"
    "sync"
	"os"
	"github.com/stalltrix/kep-demo/kepdb"
	"github.com/stalltrix/kep-demo/kepresolv"
	"github.com/stalltrix/kep-demo/send"
	"github.com/stalltrix/kep-demo/ntp"
	"github.com/stalltrix/kep-demo/limit"
	"github.com/stalltrix/kep-demo/verify"
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
	"html/template"
	"path/filepath"
	"sort"
	"github.com/stalltrix/kepweb/meta"
	"github.com/stalltrix/kepweb/notify"
	"github.com/stalltrix/kepweb/postdb"
	"github.com/stalltrix/kepweb/postcodec"
	"github.com/stalltrix/kepweb/mapvec"
	"github.com/stalltrix/kepweb/randlist"
	"github.com/stalltrix/kepweb/captcha"
	"net/netip"
	"sync/atomic"
	"kepweb-multi/sql"
	"encoding/base64"
	"kepweb-multi/user"
	"kepweb-multi/useradmin"
)

type PostIndexView struct {
    Own      string `json:"own"`
    Lasttime string `json:"lasttime"`
    Reply    int    `json:"reply"`
    Lastview string `json:"lastview"`
	Views    int  `json:"views"`
	Hex      string `json:"hex"`
	Tag      uint16 `json:"tag"`
	TypeId   byte `json:"typeid"`
	Meta     string `json:"meta"`
	SetTop   byte `json:"pintop"`
}

type ReplyRequest struct {
    PostPayload string `json:"post_payload"`
	Tag int  `json:"tag"`
	Point_to string  `json:"point_to"`
	TypeID int  `json:"typeid"`
	Nonce string `json:"nonce"`
}

type LoginType struct {
	User    string    `json:"user"`
    Token   string    `json:"token"`
	Verify  string    `json:"captcha"`
}

type indexCache struct {
    Txt []byte
	Last int64
}

type tokenLimiter struct {
    limiter   *rate.Limiter
    lastUsed  int64
}

var (
    dbStore *postdb.DataHandle
	fileIndex []byte
	fileNewPost []byte
	sessMap sync.Map
	nextroute []send.NextMsg
	nonceMap sync.Map 
	maxMarkdownSize = 60 * 1024
	Idxcache sync.Map 
	token_UrlApi string
	token_urlPort string
	sortList [65536]string
	newList [256]string
	sortIdx uint16
	newIdx byte
	二维指针 *mapvec.DataHandle
	limiterMap sync.Map
	neighborTokenMap sync.Map
	manager_csrf string
	manager_tmpl *template.Template
	will_change_reply map[string]postcodec.Reply
	top_post PostIndexView //置顶帖子
	echoMeta bool
	logDebug logger.Log_TYPE
	logInfo logger.Log_TYPE
	logWarn logger.Log_TYPE
	logErr logger.Log_TYPE
	selfdir string
	patch_perm = make(map[string]struct{})
	patch_file string
	post_prefix string
	metaoff_file string
	meta_off = make(map[string]struct{})
	adminLock sync.Mutex
	lastchange string
	isTrustCF bool
	trustFor netip.Addr
	skipSSLchk bool
	loginPage []byte
	captchaon bool
	pageViews sync.Map
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

var hexTable = [256]bool{
    '0': true, '1': true, '2': true, '3': true, '4': true,
    '5': true, '6': true, '7': true, '8': true, '9': true,
    'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true,
}

func IsHex(s string) bool {
	if len(s)!=64{
		return false
	}
    for i := 0; i < 64; i++ {
        if !hexTable[s[i]] {
            return false
        }
    }
    return true
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
	
	if len(parts[1])>5{
		http.Error(w, "post not found", http.StatusNotFound)
        return
	}
	
	is_login := false
	var uinfo *user.UserInfo
	cookie, err := r.Cookie("seesion")
	if err == nil {
		if cookie.Value != "" {
			var val interface{}
			val,is_login=sessMap.Load(cookie.Value)
			if is_login {
				uinfo=val.(*user.UserInfo)
			}
		}
	}

    postHex := parts[2]
	
	if !IsHex(postHex){
		http.Error(w, "post not found", http.StatusNotFound)
        return
	}
	
	post, ok := dbStore.Load(postHex)
	
    if !ok {
        http.Error(w, "post not found", http.StatusNotFound)
        return
    }
	
	err = viewpage(postHex)
	if err !=nil {
		logDebug.Println("log view err:",err)
	}
	
	if !is_login {
		if post.TypeID != 0 {
			http.Error(w, "post not found", http.StatusNotFound)
			return
		}
		_,ok:=patch_perm[postHex]
		if ok {
			http.Error(w, "post not found", http.StatusNotFound)
			return
		}
	} else if !uinfo.Is_admin {
		if post.TypeID > 64 {
			http.Error(w, "post not found", http.StatusNotFound)
			return
		}
		_,ok:=patch_perm[postHex]
		if ok {
			http.Error(w, "post not found", http.StatusNotFound)
			return
		}
	}
	
	if http.MethodPost==r.Method{
		if !is_login {
			w.WriteHeader(405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1 << 16)
		var req ReplyRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            w.WriteHeader(405)
            return
        }
			
		limitNum:=limit.GetLimit("reply:"+uinfo.Name)
		if limitNum > 100 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "reply rate limit exceeded"}`))
			return
		}
		
		if !strings.HasPrefix(req.Nonce,post_prefix+"_"+uinfo.Nonce) {
            w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "post format err"}`))
			return
		}
		
		if !addNonce(req.Nonce) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "duplicate"}`))
            return
        }
		
		req.Tag=0 //回帖恒为0
		hash,err:=async_send(req,uinfo)
		if err!=nil||hash=="" {
			logErr.Println("send msg err:",err)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "send msg err"}`))
			return
		}
		
		replyID:=len(post.Replies)+1
		reply := postcodec.Reply{
            ID:   replyID,
            User: uinfo.Name,
            Meta: "",
            Me:   post.Owner==uinfo.Name,
            Post: req.PostPayload,
            Time: time.Now().Unix(),
			Tag: uint16(req.Tag),
			Hex: hash,
        }
		reply.FirstTime=reply.Time
		post.Replies = append(post.Replies, reply)
        post.LastTime = reply.Time
		newV:=mapvec.Map向量{
			X: post.Replies[0].Hex,
			Y: replyID-1,
		}
		二维指针.Store(hash,newV)
		sortList[sortIdx]=post.Replies[0].Hex
		sortIdx++
		post.Replies[0].MetaTime=0
		
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
		return
	}
		
	if echoMeta {
		respReplies:=post.Replies
		time_now:=time.Now().Unix()
		if respReplies[0].MetaTime+3600 < time_now {
		respReplies[0].MetaTime=time_now
		for i:=range respReplies {
		  _,ok:=meta_off[respReplies[i].User]
		  if !ok {
			metaData,err:=meta.Meta_get(respReplies[i].User)
			if err == nil {
				respReplies[i].Meta=metaData
			}
		  }
		}
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
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
	
	if len(tagID)>5{
		http.Error(w, "invalid page", http.StatusBadRequest)
        return
	}
	tag:=-1
	if tagID != "all" && tagID != "rand" && tagID != "new" {
		tag,err=strconv.Atoi(tagID)
		if err !=nil {
			http.Error(w, "invalid page", http.StatusBadRequest)
			return
		}
		if tag <0 || tag > 65535 {
			http.Error(w, "invalid page", http.StatusBadRequest)
			return
		}
	}
	
	is_login := false
	cookie, err := r.Cookie("seesion")
	if err == nil {
		if cookie.Value != "" {
			_,is_login=sessMap.Load(cookie.Value)
		}
	}
	
	var Idxdata *indexCache
	if !is_login {
		if pageIdx > 99 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
			return
		}
		val,ok:=Idxcache.Load(tagID+":"+parts[2])
		if ok {
		Idxdata=val.(*indexCache)
		now:=int64(time.Now().Unix())
		if Idxdata.Last +40 > now {
			w.Header().Set("Content-Type", "application/json")
			w.Write(Idxdata.Txt)
			return
		}
		}
	}
	
	var posts []*postcodec.Post
	if tagID != "rand" && tagID != "new" {
	diff :=make(map[string]bool)
	i:=sortIdx
	if top_post.Hex != "" {diff[top_post.Hex]=false;}
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
			post, ok := dbStore.Load(hex)
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
			post, ok := dbStore.Load(hex)
			if ok {
				if int(post.TagID)==tag {
					diff[hex]=false
					posts = append(posts, post)
				}
			}
		}
	}
	} else if tagID == "new" {
		diff :=make(map[string]bool)
		i:=newIdx
		if top_post.Hex != "" {diff[top_post.Hex]=false;}
		for j:=0;j<256;j++{
			i--
			hex:=newList[i]
			if hex == "" {
				break
			}
			_,ok:=diff[hex]
			if ok {
				continue
			}
			post, ok := dbStore.Load(hex)
			if ok {
				diff[hex]=false
				posts = append(posts, post)
			}
		}
	} else {
		if randlist.MustRenew() {
			randlist.Renew(&sortList,sortIdx)
		}
		rndList:=randlist.GetList()
		for i:=0;i<256;i++{
			hex:=rndList[i]
			if hex == "" {
				break
			}
			post, ok := dbStore.Load(hex)
			if ok {
				posts = append(posts, post)
			}
		}
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
	if pageIdx==1 && top_post.Hex != "" {
			post_top,ok:=dbStore.Load(top_post.Hex)
			if ok {
			metaData:=""
			if echoMeta {
				_,ok:=meta_off[post_top.Owner]
				if !ok {
					metadata,err:=meta.Meta_get(post_top.Owner)
					if err == nil {
						metaData=metadata
					}
				}
			}
			line := strings.SplitN(post_top.Replies[0].Post, "\n", 2)[0]
			lastView := "[置顶] "+strings.TrimPrefix(line, "# ")
			resp = append(resp, PostIndexView{
            Own:      post_top.Owner,
            Lasttime: strconv.FormatInt(post_top.Replies[len(post_top.Replies)-1].Time, 10),
            Reply:    len(post_top.Replies),
            Lastview: lastView,
			Hex: post_top.PostHex,
			Tag: post_top.TagID,
			TypeId: post_top.TypeID,
			Meta: metaData,
			SetTop :1,
			})
			}
	}
    for _, p := range posts[start:end] {
        lastView := ""
        if len(p.Replies) > 0 {
			line := strings.SplitN(p.Replies[0].Post, "\n", 2)[0]
            lastView = strings.TrimPrefix(line, "# ")
        }
		metaData:=""
		if echoMeta {
		  _,ok:=meta_off[p.Owner]
		  if !ok {
			metadata,err:=meta.Meta_get(p.Owner)
			if err == nil {
				metaData=metadata
			}
		  }
		}
		
		viewNum:=0
		postKey, err := strconv.ParseUint(p.PostHex[:16], 16, 64)
		if err==nil{
			val,ok:=pageViews.Load(postKey)
			if ok {
				viewNum=int(*(val.(*int64)))
			}
		}

        resp = append(resp, PostIndexView{
            Own:      p.Owner,
            Lasttime: strconv.FormatInt(p.Replies[len(p.Replies)-1].Time, 10),
            Reply:    len(p.Replies),
            Lastview: lastView,
			Hex: p.PostHex,
			Tag: p.TagID,
			TypeId: p.TypeID,
			Meta: metaData,
			Views: viewNum,
        })
    }
	
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(resp)
	if err != nil {
		w.Write([]byte(`{"status":0}`))
		return
	}
	
	if pageIdx < 100 {
	if Idxdata == nil {
		newData:=&indexCache{}
		Idxcache.Store(tagID+":"+parts[2],newData)
		Idxdata=newData
	}
	Idxdata.Txt=b
	Idxdata.Last=time.Now().Unix()
	}
	w.Write(b)
}

func async_send(payload ReplyRequest,uinfo *user.UserInfo) (string,error) {
	is_verified:=sql.GetByID("verified",uinfo.ID)
	if is_verified!="1"&&is_verified!="true"{
		return "",os.ErrPermission
	}
	
	priv_base64:=sql.GetByID("priv_key",uinfo.ID)
	pub_base64:=sql.GetByID("pub_key",uinfo.ID)
	signKey_base64:=sql.GetByID("sign_key",uinfo.ID)
	mainKey_base64:=sql.GetByID("main_key",uinfo.ID)
	
	priv,err:=base64.StdEncoding.DecodeString(priv_base64)
	if err!=nil{return "",err}
	if len(priv) != ed25519.PrivateKeySize {
		return "",strconv.ErrRange
	}
	
	pub,err:=base64.StdEncoding.DecodeString(pub_base64)
	if err!=nil{return "",err}
	if len(pub) != ed25519.PublicKeySize {
		return "",strconv.ErrRange
	}
	
	signKey,err:=base64.StdEncoding.DecodeString(signKey_base64)
	if err!=nil{return "",err}
	if len(signKey) != ed25519.PrivateKeySize {
		return "",strconv.ErrRange
	}
	
	mainPub,err:=base64.StdEncoding.DecodeString(mainKey_base64)
	if err!=nil{return "",err}
	if len(mainPub) != ed25519.PublicKeySize {
		return "",strconv.ErrRange
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
			logErr.Println("send reply err:",err)
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
	
	_,err=verify.ParseAndVerify(msg)
	if err != nil {
		return hashHex,err
	}
	
	//go func(){
	err = send.Nextmsg(msg,"",skipSSLchk)
	if err != nil {
		//logErr.Println("send msg err:",err)
		return hashHex,err
	}
	//}()
	return hashHex,nil
}

func loadData(tag string,renew bool){
		hexs,err:=kepdb.ReadHash(tag)
			if err ==nil {
			dat,err:=kepresolv.Resolv(hexs)
			if err !=nil {
				logWarn.Println("load data err:",err)
				return;
			}
			txt:=dat.Atxt
			domain:=dat.Adomain
			timestamp:=dat.Atimestamp
			point_to:=dat.Apoint_to
			perm:=dat.Aperm
			key_des:=dat.Akey_des
			tag_i:=dat.Atag2
			if point_to != nil {
				//回帖子内容，跳过
				if !renew{
					//logDebug.Println("回帖子内容，跳过")
				} else {
					o_hex:=hex.EncodeToString(point_to)
					o_hexs,err:=kepdb.ReadHash(o_hex)
					if err!=nil {
						logWarn.Println("ERR: 找不到原始帖子",err)
						return
					}
					dat,err:=kepresolv.Resolv(o_hexs)
					o_domain:=dat.Adomain
					o_key_des:=dat.Akey_des
					o_tag_i:=dat.Atag2
					if err!=nil {
						logErr.Println("ERR: 原始帖子err",err)
						return
					}
					nowV,ok:=二维指针.Load(o_hex)
					if !ok {
						logWarn.Println("drop wild point hex:",o_hex)
						return;
					}
					o_post,ok:=dbStore.Load(nowV.X)
				if ok {
					if tag_i == 65534 {
						if (key_des == o_key_des) && bytes.Equal(domain,o_domain){
						if nowV.Y == 0 {
						if timestamp > o_post.Replies[0].Time{
							o_post.TypeID=byte(perm & 255)
							first_time:=o_post.Replies[0].FirstTime
							meta_data:=o_post.Replies[0].Meta
							o_post.Replies[0]=postcodec.Reply{ID: 1, User: string(domain), Meta: meta_data, Me: true, Post: string(txt), Time: timestamp, FirstTime: first_time, Tag: o_tag_i, Hex: o_hex}
						}}else {
							if len(o_post.Replies)>nowV.Y{
								if timestamp > o_post.Replies[nowV.Y].Time{
								first_time:=o_post.Replies[nowV.Y].FirstTime
								meta_data:=o_post.Replies[nowV.Y].Meta
								me_data:=o_post.Replies[nowV.Y].Me
								o_post.Replies[nowV.Y]=postcodec.Reply{ID: nowV.Y+1, User: string(domain), Meta: meta_data, Me: me_data, Post: string(txt), Time: timestamp, FirstTime: first_time, Tag: o_tag_i, Hex: o_hex}
								}
							}
						}}
						return
					}
						lastID:=len(o_post.Replies)
						o_post.Replies = append(o_post.Replies, postcodec.Reply{
    ID:   lastID+1,
    User: string(domain),
    Meta: "",
    Me:   (key_des == o_key_des) && bytes.Equal(domain,o_domain),
    Post: string(txt),
    Time: timestamp,
	FirstTime: timestamp,
	Tag: tag_i,
	Hex: tag,
 })
 	newV:=mapvec.Map向量{
		X: o_hex,
		Y: lastID,
	}
	二维指针.Store(tag,newV)
	o_post.Replies[0].MetaTime=0
	sortList[sortIdx]=o_hex
	sortIdx++
				}
				}
				return;
			}
			var newRly = []postcodec.Reply{{ID: 1, User: string(domain), Meta: "", Me: true, Post: string(txt), Time: timestamp, FirstTime: timestamp, Tag: tag_i, Hex: tag},}
			var lastID=2
			subs,err:=kepdb.ReadSub(tag)
			if err ==nil {
for _,sub := range subs {
	hex_byte,err:=kepdb.ReadHash(sub)
	if err ==nil {
	dat,err:=kepresolv.Resolv(hex_byte)
 txt2:=dat.Atxt
 domain2:=dat.Adomain
 timestamp2:=dat.Atimestamp
 point_to2:=dat.Apoint_to
 perm2:=dat.Aperm
 key_des2:=dat.Akey_des
 tagi2:=dat.Atag2
 if err !=nil {
	logInfo.Println("load data err:",err)
	continue;
	}
	if tagi2 == 65534 {
		o_hex2:=hex.EncodeToString(point_to2)
		if o_hex2 == tag {
		if (key_des == key_des2) && bytes.Equal(domain,domain2) {
			//本人
			if timestamp2 > newRly[0].Time{
			newRly[0]=postcodec.Reply{
    ID:   1,
    User: string(domain2),
    Meta: "",
    Me:   true,
    Post: string(txt2),
    Time: timestamp2,
	FirstTime: timestamp,
	Tag: tag_i,
	Hex: tag,
			}
	perm=perm2
		}}
		}
		continue;
	}
 newRly = append(newRly, postcodec.Reply{
    ID:   lastID,
    User: string(domain2),
    Meta: "",
    Me:   (key_des == key_des2) && bytes.Equal(domain,domain2),
    Post: string(txt2),
    Time: timestamp2,
	FirstTime: timestamp2,
	Tag: tagi2,
	Hex: sub,
 })
 	newV:=mapvec.Map向量{
		X: tag,
		Y: lastID-1,
	}
	二维指针.Store(sub,newV)
 lastID++
	}
}
			}
	sort.Slice(newRly, func(i, j int) bool {
		if i==0||j==0{
			return false
		}
		return newRly[i].FirstTime < newRly[j].FirstTime
	})	
    dbStore.Store(tag,&postcodec.Post{
        PostHex: tag,
        TagID:   tag_i,
        Owner:   string(domain),
        LastTime: timestamp,
        Replies: newRly,
		TypeID: perm,
    })
	newV:=mapvec.Map向量{
		X: tag,
		Y: 0,
	}
	二维指针.Store(tag,newV)
	sortList[sortIdx]=tag
	sortIdx++
	newList[newIdx]=tag
	newIdx++
		}
}

func initData() {
	for i:=0;i<16;i++{
		tags,err:=kepdb.ReadTag(i)
		if err ==nil {
			err=notify.Reg_fs(i,callback_renew)
			if err!=nil {
				logWarn.Println("reg tag err:",err)
			}
			for _,tag := range tags {
				loadData(tag,false);}}
	}
	/*tags,err:=kepdb.ReadTag(65534)
	if err ==nil {
	will_change_reply=make(map[string]postcodec.Reply);
	for _,tag := range tags {
	hexs,err:=kepdb.ReadHash(tag)
	if err ==nil {
	dat,err:=kepresolv.Resolv(hexs)
	txt:=dat.Atxt
	domain:=dat.Adomain
	timestamp:=dat.Atimestamp
	point_to:=dat.Apoint_to
	key_des:=dat.Akey_des
	point_to_root:=dat.Aroot
	tag_i:=dat.Atag2
			if err !=nil {
				logInfo.Println("load data err:",err)
				continue;
			}
			if len(point_to_root)<4{
				continue;
			}
		point_to_hex:=hex.EncodeToString(point_to)
		hexbyte,err:=kepdb.ReadHash(point_to_hex)
		if err!=nil{
			logInfo.Println("debug: point_to_hex not found",err)
			continue;
		}
		o_dat,err:=kepresolv.Resolv(hexbyte)
		ori_domain:=o_dat.Adomain
		ori_key_des:=o_dat.Akey_des
		if err!=nil{
			logInfo.Println("debug: point msg not found",err)
			continue;
		}
		if !(bytes.Equal(ori_domain,domain) && (ori_key_des==key_des)){
			logInfo.Println("mot match ori_ley",string(domain))
			continue;
		}
		
		point_root:=hex.EncodeToString(point_to_root)
		rootbyte,err:=kepdb.ReadHash(point_root)
		if err!=nil{
			logInfo.Println("debug: point_to_root not found",err)
			continue;
		}
		o2_dat,err:=kepresolv.Resolv(rootbyte)
		ori_domain_root:=o2_dat.Adomain
		ori_key_des_root:=o2_dat.Akey_des
		if err!=nil{
			logInfo.Println("debug: point root msg not found",err)
			continue;
		}
		nowRly,ok:=will_change_reply[point_to_hex]
		if !ok {
	will_change_reply[point_to_hex]=postcodec.Reply{
    ID:   0,
    User: string(domain),
    Meta: "",
    Me:   bytes.Equal(ori_domain_root,domain) && (ori_key_des_root==key_des),
    Post: string(txt),
    Time: timestamp,
	Tag: tag_i,
	Hex: point_to_hex,
	}
	}else{
		if timestamp > nowRly.Time{
	will_change_reply[point_to_hex]=postcodec.Reply{
    ID:   0,
    User: string(domain),
    Meta: "",
    Me:   bytes.Equal(ori_domain_root,domain) && (ori_key_des_root==key_des),
    Post: string(txt),
    Time: timestamp,
	Tag: tag_i,
	Hex: point_to_hex,
	}
		}
	}}}
	for k,v:=range will_change_reply {
		nowV,ok:=二维指针.Load(k)
		if ok {
    post,ok:=dbStore.Load(nowV.X)
	if ok {
		if len(post.Replies)>nowV.Y{
			if post.Replies[nowV.Y].Time < v.Time {
			v.ID=nowV.Y+1
			v.FirstTime=post.Replies[nowV.Y].FirstTime
			post.Replies[nowV.Y]=v
			}
		}
	}
		}else{
			logInfo.Println("debug: post not found",k)
		}
	}
	will_change_reply=nil
	}*/
	callback_change(65534)
	err:=notify.Reg_fs(65534,callback_change)
	if err!=nil {
		logWarn.Println("reg tag err:",err)
	}
	sort.Slice(sortList[:sortIdx], func(i, j int) bool {
		if sortList[i]==""||sortList[j]==""{
			return false
		}
		return getLastPost(sortList[i]) < getLastPost(sortList[j])
	})
	sort.Slice(newList[:newIdx], func(i, j int) bool {
		if newList[i]==""||newList[j]==""{
			return false
		}
		return getpostTime(newList[i]) < getpostTime(newList[j])
	})
}

func getLastPost(hex string) int64 {
	if hex == "" {
		return 0
	}
	post, ok := dbStore.Load(hex)
	if ok {
		if len(post.Replies)==0{
			return 0
		}
		return post.Replies[len(post.Replies)-1].FirstTime
	}
	return 0
}

func getpostTime(hex string) int64 {
	if hex == "" {
		return 0
	}
	post, ok := dbStore.Load(hex)
	if ok {
		return post.LastTime
	}
	return 0
}

func callback_renew(tag_id int){
    idxPath := filepath.Join(selfdir, "tag_"+strconv.Itoa(tag_id)+".idx")
    f, err := os.Open(idxPath)
    if err != nil {
		logWarn.Println("renew err:",err)
        return
    }
    defer f.Close()

    stat, err := f.Stat()
    if err != nil {
		logWarn.Println("renew err:",err)
        return
    }

    size := stat.Size()
	
	const lineSize = 65

    for offset := size - lineSize; offset >= 0; offset -= lineSize {
        buf := make([]byte, lineSize)

        _, err := f.ReadAt(buf, offset)
        if err != nil && err != io.EOF {
			logWarn.Println("renew err:",err)
            return
        }
		tag:=string(buf[:64])
		_,ok:=二维指针.Load(tag)
		if ok {
			logDebug.Println("debug: renew endof:",tag)
			return
		}
		logDebug.Println("debug: renew data:",tag)
        loadData(tag,true)
    }
}

func callback_change(tag_id int){
	if tag_id!=65534{
		logWarn.Println("reg tag err: !65534")
        return
	}
    idxPath := filepath.Join(selfdir, "tag_65534.idx")
    f, err := os.Open(idxPath)
    if err != nil {
		logWarn.Println("renew err:",err)
        return
    }
    defer f.Close()

    stat, err := f.Stat()
    if err != nil {
		logWarn.Println("renew err:",err)
        return
    }

    size := stat.Size()
	
	const lineSize = 65

    var changed_tag string
	for offset := size - lineSize; offset >= 0; offset -= lineSize {
        buf := make([]byte, lineSize)

        _, err := f.ReadAt(buf, offset)
        if err != nil && err != io.EOF {
			logWarn.Println("renew err:",err)
            return
        }
		tag:=string(buf[:64])
		if tag==lastchange {
			logDebug.Println("debug: renew endof:",tag)
			return
		}
		logDebug.Println("debug: renew data:",tag)
        loadData(tag,true)
		if changed_tag=="" {
			changed_tag=tag
		}
    }
	if changed_tag!="" {
		lastchange=changed_tag
	}
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
		info:=val.(*user.UserInfo)
		
		metaData,err:=meta.Meta_get(info.Name)
		if err != nil {
			metaData="https://avatar.stalltrix.com/avatar/"+url.QueryEscape(info.Name)+".svg"
		} else {
			var ImgData struct {
				Name string `json:"name"`
				Img  string `json:"img"`
			}
			err = json.Unmarshal([]byte(metaData), &ImgData)
			if err != nil {
				metaData="https://avatar.stalltrix.com/avatar/"+url.QueryEscape(info.Name)+".svg"
			} else {
				if ImgData.Img==""{
					if ImgData.Name==""{
						ImgData.Name=info.Name
					}
					metaData="https://avatar.stalltrix.com/avatar/"+url.QueryEscape(ImgData.Name)+".svg"
				} else {
					metaData=ImgData.Img
				}
			}
		}
		
		w.Write([]byte(`{"status":1,"user":"`+info.Name+`","img":"`+metaData+`","nonce":"`+post_prefix+"_"+info.Nonce+`"}`))
}
func logoffHandler(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.Write([]byte(`{"status":0}`))
			return
		}
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
		
		r.Body = http.MaxBytesReader(w, r.Body, 1 << 10)
		var req ReplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Write([]byte(`{"status":0}`))
			return
		}
		
		expired:=val.(*user.UserInfo)
		
		if !strings.HasPrefix(req.Nonce,post_prefix+"_"+expired.Nonce) {
			w.Write([]byte(`{"status":0}`))
			return
		}
		expired.Sess.Stop()
		sessMap.Delete(cookie.Value)
		w.Write([]byte(`{"status":1}`))
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/html")
		cookie, err := r.Cookie("seesion")
		if err == nil {
			_,ok:=sessMap.Load(cookie.Value)
			if ok {
				http.Redirect(w, r, "/index.php", http.StatusFound)
				return
			}
		}
		w.Write(loginPage)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	r.Body = http.MaxBytesReader(w, r.Body, 1 << 10)
	var req LoginType
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.Write([]byte(`{"status":0}`))
        return
    }
	
	if len(req.Token) <8 {
		w.Write([]byte(`{"status":0}`))
        return
	}
	
	if len(req.User)>64||len(req.User)<3 {
		w.Write([]byte(`{"status":0}`))
        return
	}
	
	real_ip := r.RemoteAddr
	if idx := strings.LastIndex(real_ip, ":"); idx != -1 {
		real_ip = real_ip[:idx]
		if len(real_ip)>2 && real_ip[0]=='[' && real_ip[len(real_ip)-1]==']' {
			real_ip=real_ip[1:len(real_ip)-1]
		}
	}
	
	numIP, err := netip.ParseAddr(real_ip)
    if err != nil {
        w.Write([]byte(`{"status":0}`))
        return
    }
	IsPrivateNet:=numIP.IsPrivate() || numIP.IsLoopback()
	if trustFor.IsValid() && numIP==trustFor{
		IsPrivateNet=true
	}
	user_ip := ""
	if isTrustCF {
		user_ip = r.Header.Get("CF-Connecting-IP")
	} else {
		if IsPrivateNet {
			user_ip = r.Header.Get("X-Forwarded-For")
			if user_ip=="" {
				user_ip = real_ip
			} else if strings.Index(user_ip, ",") != -1 {
				getip:=false
				cf_ip := r.Header.Get("CF-Connecting-IP")
				ips := strings.Split(strings.ReplaceAll(user_ip, " ", ""), ",")
				if len(ips) > 1 {
					if ips[len(ips)-1]==cf_ip{
						user_ip = cf_ip
						getip=true
					}
				}
				if !getip{
					if len(ips) > 1 {
						for i:=len(ips)-1;i>=0;i--{
							ip,err:= netip.ParseAddr(ips[i])
							if err == nil {
								if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && numIP!=ip {
									user_ip = ips[i]
									getip=true
									break
								}
							}
						}
					}
					if !getip&&len(ips)!=0{
						user_ip = ips[0]
					}
				}
			}
		} else {
			user_ip = real_ip
		}
	}
	
	if captchaon {
		if req.Verify==""{
			logDebug.Println("login captcha is null")
			w.Write([]byte(`{"status":0}`))
			return
		}
		err=captcha.Verify_f(req.Verify)
		if err !=nil {
			logDebug.Println("login captcha fail",err)
			w.Write([]byte(`{"status":0}`))
			return
		}
	}
	
	ipaddr := user_ip
	if len(user_ip) > 19 {
		ipaddr=user_ip[:19]
	}
	limiter := getLimiter(ipaddr)
    if !limiter.Allow() {
        logInfo.Println("WARN: Rate limit exceeded ,ip:", user_ip)
        w.Write([]byte(`{"status":0}`))
		return
    }
	
	id:=sql.Search("name",req.User)
	
	if id<0 {
		w.Write([]byte(`{"status":0}`))
        return
	}
	
	SQL_hash:=sql.GetByID("passwd",id)
	
	if SQL_hash=="" {
		w.Write([]byte(`{"status":0}`))
        return
	}
	
	hash1:=sha256.Sum256([]byte(req.Token))
	
	pwd_hash := hex.EncodeToString(hash1[:])
	if SQL_hash!=pwd_hash {
		w.Write([]byte(`{"status":0}`))
        return
	}
	
	is_banned:=sql.GetByID("is_banned",id)
	if is_banned=="1"{
		w.Write([]byte(`{"status":-1}`))
        return
	}
	
	sess,err:=randSess(32)
	if err !=nil {
		logWarn.Println(err)
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
	
	newNonce,err:=randSess(6)
	if err!=nil {
		newNonce=strconv.Itoa(int(time.Now().Unix())&0xffff)
	}
	
	domain:=sql.GetByID("domain",id)
	
	admin:=sql.GetByID("is_admin",id)

	info:=&user.UserInfo {
		UserID: req.User,
		Name: domain,
		ID: id,
		Is_admin: admin=="admin",
		Nonce: newNonce,
	}
	
	sessMap.Store(sess,info)
	expired:=time.AfterFunc(3600*24*15*time.Second, func() {
		sessMap.Delete(sess)
	})
	info.Sess=expired
	w.Write([]byte(`{"status":1,"user":"`+info.Name+`","img":"https://avatar.stalltrix.com/avatar","nonce":"`+post_prefix+"_"+info.Nonce+`"}`))
}

func main() {
	argc:=len(os.Args)
	if argc <=1 {
		logger.Print("usage:")
		logger.Print("\twebserver [config.json] [logfile]")
		logger.Print("\twebserver -cli command")
		return
	}
	cfg_file:=os.Args[1]
	
	if cfg_file=="-v" {
		logger.Print("webserver-multi: v0.2.0")
		return
	}
	
	if cfg_file=="-cli" {
		if argc <=4 {
			logger.Print("usage:")
			logger.Print("webserver -cli [command]")
			logger.Print("\t-cli [config.json] adduser [username]")
			logger.Print("\t-cli [config.json] banuser [username]")
			logger.Print("\t-cli [config.json] setadmin [username]")
			logger.Print("\t-cli [config.json] deladmin [username]")
			logger.Print("\t-cli [config.json] resetpass [username]")
			return
		}
		cfg,err := config.Resolv(os.Args[2])
		if err!=nil {
			logger.Fatalln("can't read config.json",err)
		}
		cmd:=os.Args[3]
		user:=os.Args[4]
		err=useradmin.SetKeyFile(cfg.Keyfile)
		if err!=nil{
			logger.Fatalln("Warn: set keyfile fail:",err)
		}
		err=sql.Conn(cfg.SQLip,cfg.SQLpass)
		if err!=nil{
			logger.Fatalln("Err: connect sql database:",err)
		}
		if user==""{
			logger.Print("username is null")
			return
		}
		if cmd=="adduser" {
			pass,err:=randSess(8)
			if err!=nil{
				logger.Fatalln(err)
			}
			err=useradmin.NewUser(user,pass)
			if err!=nil{
				logger.Fatalln("add user fail:",err)
			}
			logger.Print("add user success, username="+user+" , pass="+pass)
		} else if cmd=="resetpass" {
			pass,err:=randSess(8)
			if err!=nil{
				logger.Fatalln(err)
			}
			err=useradmin.ForceResetPasswd(user,pass)
			if err!=nil{
				logger.Fatalln("reset password fail:",err)
			}
			logger.Print("reset password success, username="+user+" , pass="+pass)
		} else if cmd=="banuser" {
			err=useradmin.BanUser(user)
			if err!=nil{
				logger.Fatalln("ban user fail:",err)
			}
			logger.Print("ban user success, username="+user+" is banned")
		} else if cmd=="setadmin" {
			id:=sql.Search("name",user)
			if id<0 {
				logger.Fatalln(sql.NotFoundErr)
			}
			err:=sql.Set("is_admin","admin",id)
			if err!=nil {
				logger.Fatalln("set admin fail:",err)
			}
			logger.Print("set admin success, username="+user+" is admin now")
		} else if cmd=="deladmin" {
			id:=sql.Search("name",user)
			if id<0 {
				logger.Fatalln(sql.NotFoundErr)
			}
			err:=sql.Set("is_admin","",id)
			if err!=nil {
				logger.Fatalln("del admin fail:",err)
			}
			logger.Print("del admin success, username="+user+" no longer admin")
		}
		return
	}
	
	var err error
	self:=""
	exePath, err := os.Executable()
    if err == nil {
		self = filepath.Dir(exePath)
		kepdb.Init_path(self)
		selfdir=filepath.Join(self, "kep-data")
    }else{
		selfdir="kep-data"
		logger.Print("find self dir err: "+err.Error())
		time.Sleep(time.Second*12)
	}
	
	fileNewPost,err=os.ReadFile(filepath.Join(self, "markdown.html"))
	if err!=nil {
		logger.Fatalln("can't read markdown.html",err)
	}
	
	manager_tmpl,err=template.ParseFiles(filepath.Join(self, "manager.html"))
	if err!=nil {
		logger.Fatalln("can't read manager.html",err)
	}
		
	loginPage,err=os.ReadFile(filepath.Join(self, "login.html"))
	if err!=nil {
		logger.Fatalln("can't read login.html",err)
	}
	
	dashPage,err:=os.ReadFile(filepath.Join(self, "account.html"))
	if err!=nil {
		logger.Fatalln("can't read account.html",err)
	}
	user.LoadPage(dashPage)
	
	cfg,err := config.Resolv(cfg_file)
	if err!=nil {
		logger.Fatalln("can't read config.json",err)
	}
	
	if cfg.LogLevel == "" {
		cfg.LogLevel="info"
	}
	
    logger.SYS_Level(cfg.LogLevel)
    logDebug.SetLevel("debug")
    logInfo.SetLevel("info")
    logWarn.SetLevel("warn")
    logErr.SetLevel("err")
	
	fileIndex,err=os.ReadFile(filepath.Join(self, "ui.html"))
	if err!=nil {
		logger.Fatalln("can't read ui.html",err)
	}
	
	if cfg.Keyfile=="" {
		logger.Fatal("Err: keyfile is null")
	}
	if len(cfg.ApiToken) < 8 {
		logger.Fatal("Err: token is null")
	}
	token_UrlApi=cfg.ApiToken
	echoMeta = cfg.Metaon
	
	if cfg.Dbfile == ""{
		cfg.Dbfile=filepath.Join(os.TempDir(), "db-")
	}
	dbStore,err=postdb.Open(cfg.Dbfile,cfg.DbAddr,cfg.DbPass)
	if err != nil {
		logger.Fatalln("Err: open db err:",err)
	}
	is_same:=(cfg.VecAddr==cfg.DbAddr)&&(cfg.VecPass==cfg.DbPass)
	二维指针,err=mapvec.New(cfg.VecAddr,cfg.VecPass,is_same)
	if err != nil {
		logger.Fatalln("Err: open vec-db err:",err)
	}
	
	nextroute=make([]send.NextMsg,len(cfg.Neighbors))
	for i:= range nextroute {
		nextroute[i].Addr=cfg.Neighbors[i].URL
		nextroute[i].Auth=cfg.Neighbors[i].Token
	}
	
	send.Send_Init(nextroute,cfg.Socks5,cfg.SkipSSLchk)
	
	if cfg.Ntp != "" {
		ntp.Ntp_Init(cfg.Ntp)
		logWarn.Println("start ntp client:",cfg.Ntp)
	}
	
	err=useradmin.SetKeyFile(cfg.Keyfile)
	if err!=nil{
		logWarn.Println("Warn: set keyfile fail:",err)
	}
	
	err=sql.Conn(cfg.SQLip,cfg.SQLpass)
	if err!=nil{
		logger.Fatalln("Err: connect sql database:",err)
	}
	
	err=loadPageView(filepath.Join(self, "pageview.json"))
	if err!=nil{
		logWarn.Println("WARN: read pageview err:",err)
	}
	
	notify.Init_path(self)
	initData()
	
    http.HandleFunc("/view/", viewHandler)
    http.HandleFunc("/index/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logoff", logoffHandler)
	http.HandleFunc("/me", meHandler)
	http.HandleFunc("/index.php", indexpage)
	http.HandleFunc("/t/topic/", topicpage)
	http.HandleFunc("/manager", managerHandler)
	http.HandleFunc("/user/", userHandler)
	http.HandleFunc("/about", aboutHandler)
	
	staticFS, _ := fs.Sub(staticFiles, "static")

    http.Handle("/static/",
        http.StripPrefix("/static/",
            http.FileServer(http.FS(staticFS)),
        ),
    )
	
	if cfg.Listen == "" {
		logger.Fatal("Err: listen addr is null:")
		return
	}
	
	token_urlPort = cfg.Apiport
	
	notify.Done()
	if token_urlPort == "" {
		token_urlPort="10428"
	}
	if cfg.SkipSSLchk {
		skipSSLchk=cfg.SkipSSLchk
		logWarn.Println("Warn: skip SSL check: on")
	}
	if cfg.TrustCFIP {
		isTrustCF=cfg.TrustCFIP
	}
	if cfg.TrustFor!="" {
		trustFor,err=netip.ParseAddr(cfg.TrustFor)
		if err != nil {
			logger.Fatalln("Err: trust IP addr is invalid:",err)
			return
		}
	}
	if cfg.Captcha.ServerAddr != "" && cfg.Captcha.SecretKey!="" {
		if !strings.HasPrefix(cfg.Captcha.ServerAddr,"http"){
			logger.Fatal("ERR: set captcha addr err: url format err, "+cfg.Captcha.ServerAddr)
		}
		logWarn.Println("init: set captcha on, addr:",cfg.Captcha.ServerAddr)
		captchaon=true
		captcha.Set(cfg.Captcha.ServerAddr,cfg.Captcha.SecretKey,cfg.Captcha.UA)
	}
	patch_file=cfg.Permfile
	if patch_file=="" {
		patch_file=filepath.Join(self, "perm.ini")
	}
	err=pbbLoad()
	if err != nil {
		logWarn.Println("Warn: load perm file:",err)
	}
	metaoff_file=cfg.Metaofffile
	if metaoff_file=="" {
		metaoff_file=filepath.Join(self, "metaoff.json")
	}
	err=metaoffLoad()
	if err != nil {
		logWarn.Println("Warn: load metaoff file:",err)
	}

    logWarn.Println("server started on: ",cfg.Listen)
	if argc >2 {
	logfile:=os.Args[2]
	logpath,err :=os.OpenFile(logfile,os.O_WRONLY|os.O_CREATE|os.O_APPEND,0644)
	if err != nil {
		logErr.Println(err)
		return
	}
	logger.SetOutput(logpath)
	}
	go auto_renew_csrf();
	go meta.NewTTLMap()
	go autoSave(self)
	go startLimiterCleaner()
	go verify.NewTTLMap()
    logger.Fatalln(http.ListenAndServe(cfg.Listen, nil))
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("管理员未设置about页面"))
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("seesion")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	val,ok:=sessMap.Load(cookie.Value)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	
	uinfo:=val.(*user.UserInfo)
	path1:=strings.TrimPrefix(r.URL.Path,"/user/")
		
	if path1=="" {
		http.Redirect(w, r, "/user/dashboard", http.StatusFound)
		return
	}
	
	if path1=="dashboard" {
		user.DashHandler(w,r,uinfo)
		return
	}
	
	if path1=="api/info" {
		user.InfoHandler(w,r,uinfo)
		return
	}
	
	if path1=="api/passwd" {
		user.PasswdHandler(w,r,uinfo)
		return
	}
	
	if path1=="api/domain" {
		user.DomainHandler(w,r,uinfo)
		return
	}
	
	if path1=="api/verifyrequest" {
		user.VerifyHandler(w,r,uinfo)
		return
	}
	http.NotFound(w, r)
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
		
		info:=val.(*user.UserInfo)
		if !info.Is_admin {
			w.WriteHeader(403)
            w.Write([]byte("access deny"))
            return
		}
		
		state:=sql.GetByID("is_admin",info.ID)
		if state!="admin"{
			w.WriteHeader(403)
            w.Write([]byte("access deny"))
            return
		}
		
	type User struct {
		Req string `json:"req"`
		Act string `json:"act"`
		Csrf string `json:"csrf"`
		Url string `json:"url"`
		RPM int `json:"rpm"`
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
        io.WriteString(w, formatError(err))
        return
    }

    body, err := io.ReadAll(resp.Body)
    resp.Body.Close()

    if err != nil {
        io.WriteString(w, formatError(err))
        return
    }

    type ApiResp struct{
        State string   `json:"state"`
        Data  []string `json:"data"`
		Url   []string `json:"url"`
    }

    var api ApiResp
	
	//log.Println("debug: list=",string(body))

    err = json.Unmarshal(body,&api)
    if err != nil {
        io.WriteString(w, formatError(err))
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
		Url   []string `json:"url"`
    }{
        State:"OK",
        Data:result,
		Url:api.Url,
    }

    w.Header().Set("Content-Type","application/json")
    json.NewEncoder(w).Encode(out)
}
case "ban":{
	if strings.Contains(act, ":") {
	if strings.HasSuffix(act, "me:") {
		domain:=strings.TrimPrefix(act,"me:")
		id:=sql.Search("domain",domain)
		if id<0 {
			io.WriteString(w,`{"state":"user not found"}`)
			return
		}
		is_banned:=sql.GetByID("is_banned",id)
		if is_banned=="1"{
			io.WriteString(w,`{"state":"`+domain+` already banned"}`)
			return
		}
		err=sql.Set("is_banned","1",id)
		if err==nil {
			io.WriteString(w,`{"state":"OK"}`)
		} else {
			io.WriteString(w, formatError(err))
		}
		logWarn.Println("[management log] ban domain:"+domain+" reason:"+Ner_url)
	}else if strings.HasSuffix(act, "user:") {
		user:=strings.TrimPrefix(act,"user:")
		id:=sql.Search("name",user)
		if id<0 {
			io.WriteString(w,`{"state":"user not found"}`)
			return
		}
		is_banned:=sql.GetByID("is_banned",id)
		if is_banned=="1"{
			io.WriteString(w,`{"state":"`+user+` already banned"}`)
			return
		}
		err=sql.Set("is_banned","1",id)
		if err==nil {
			io.WriteString(w,`{"state":"OK"}`)
		} else {
			io.WriteString(w, formatError(err))
		}
		logWarn.Println("[management log] ban user:"+user+" reason:"+Ner_url)
	}else{
		io.WriteString(w,`{"state":"req err, need me:domain or user:username"}`)
	}
	return
	}
	url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=ban&req="+url.QueryEscape(act)+"&token="+token_UrlApi
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w, formatError(err))
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		io.WriteString(w, formatError(err))
		return
	}
	logWarn.Println("[management log] ban domain:"+act+" reason:"+Ner_url)
	io.WriteString(w,`{"state":"`+string(body)+`"}`)
}
case "unban":{
	if strings.Contains(act, ":") {
	if strings.HasSuffix(act, "me:") {
		domain:=strings.TrimPrefix(act,"me:")
		id:=sql.Search("domain",domain)
		if id<0 {
			io.WriteString(w,`{"state":"user not found"}`)
			return
		}
		is_banned:=sql.GetByID("is_banned",id)
		if is_banned!="1"{
			io.WriteString(w,`{"state":"`+domain+` is not ban"}`)
			return
		}
		err=sql.Set("is_banned","",id)
		
		if err==nil {
			io.WriteString(w,`{"state":"OK"}`)
		} else {
			io.WriteString(w, formatError(err))
		}
	}else if strings.HasSuffix(act, "user:") {
		user:=strings.TrimPrefix(act,"user:")
		id:=sql.Search("name",user)
		if id<0 {
			io.WriteString(w,`{"state":"user not found"}`)
			return
		}
		is_banned:=sql.GetByID("is_banned",id)
		if is_banned!="1"{
			io.WriteString(w,`{"state":"`+user+` is not ban"}`)
			return
		}
		err=sql.Set("is_banned","",id)
		
		if err==nil {
			io.WriteString(w,`{"state":"OK"}`)
		} else {
			io.WriteString(w, formatError(err))
		}
	}else{
		io.WriteString(w,`{"state":"req err, need me:domain or user:username"}`)
	}
	return
	}
	url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=unban&req="+url.QueryEscape(act)+"&token="+token_UrlApi
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w, formatError(err))
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		io.WriteString(w, formatError(err))
		return
	}
	io.WriteString(w,`{"state":"`+string(body)+`"}`)
}
case "pmsg":{
	//私信
	//TODO:
	io.WriteString(w,`{"state":"TODO..."}`)
}
case "multiuser":{
	switch user.RPM {
	case 1:
		err=useradmin.NewUser(act,Ner_url)
		if err!=nil {
			if err==sql.NotFoundErr {io.WriteString(w,`{"state":"user not found"}`);return;}
			io.WriteString(w, formatError(err))
			return
		}
		io.WriteString(w,`{"state":"multi-user: adduser OK"}`)
	case 2:
		err=useradmin.ForceResetPasswd(act,Ner_url)
		if err!=nil {
			if err==sql.NotFoundErr {io.WriteString(w,`{"state":"user not found"}`);return;}
			io.WriteString(w, formatError(err))
			return
		}
		io.WriteString(w,`{"state":"multi-user: reset password OK"}`)
	case 3:
		err=useradmin.BanUser(act)
		if err!=nil {
			if err==sql.NotFoundErr {io.WriteString(w,`{"state":"user not found"}`);return;}
			io.WriteString(w, formatError(err))
			return
		}
		io.WriteString(w,`{"state":"multi-user: ban user OK"}`)
	case 4:
		err=useradmin.UnBanUser(act)
		if err!=nil {
			if err==sql.NotFoundErr {io.WriteString(w,`{"state":"user not found"}`);return;}
			io.WriteString(w, formatError(err))
			return
		}
		io.WriteString(w,`{"state":"multi-user: unban user OK"}`)
	default:
		io.WriteString(w,`{"state":"multi-user: method not found"}`)
	}
}
case "metaoff":{
	_,ok=meta_off[act]
	if Ner_url == "0" {
	//remove
		if !ok {
			io.WriteString(w,`{"state":"remove meta-off: user not found"}`)
			return
		}
	} else {
		if ok {
			io.WriteString(w,`{"state":"set meta-off: user exist"}`)
			return
		}
	}
	adminLock.Lock()
	meta_off=changeMap(meta_off,act,Ner_url!="0")
	data, err := json.Marshal(meta_off)
	if err == nil {
		os.WriteFile(metaoff_file, data, 0600)
	}
	adminLock.Unlock()
	io.WriteString(w,`{"state":"set meta-off: OK"}`)
}
case "perm":{
	_,ok:=dbStore.Load(act)
	if !ok {
		io.WriteString(w,`{"state":"set-perm: post not found"}`)
		return
	}
	if Ner_url != "0" && Ner_url != "1" {
		io.WriteString(w,`{"state":"new perm is null"}`)
		return
	}
	//管理员界面，先默认无并发。以后再完善
	adminLock.Lock()
	defer adminLock.Unlock()
	if Ner_url == "0" {
		//remove
		_,ok=patch_perm[act]
		if ok {
			err = removeKey(act)
			if err != nil {
				io.WriteString(w, formatError(err))
				return
			}
			patch_perm=changeMap(patch_perm,act,false)
		}
	} else {
		//add
		f,err:= os.OpenFile(patch_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			io.WriteString(w, formatError(err))
			return
		}
		_, err = f.WriteString(act+":1\n")
		if err != nil {
			f.Close()
			io.WriteString(w, formatError(err))
			return
		}
		f.Close()
		patch_perm=changeMap(patch_perm,act,true)
	}
	io.WriteString(w,`{"state":"set-perm: OK"}`)
}
case "resend":{
	_,ok:=二维指针.Load(act)
	if !ok {
		io.WriteString(w,`{"state":"resend: post not found"}`)
		return
	}
	url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=resend&req="+url.QueryEscape(act)+"&token="+token_UrlApi
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w, formatError(err))
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		io.WriteString(w, formatError(err))
		return
	}
	io.WriteString(w,`{"state":"`+string(body)+`"}`)
}
case "tag":{
	//修改tag
	post_tag,ok:=dbStore.Load(act)
	if !ok {
		io.WriteString(w,`{"state":"change-tag: post not found"}`)
		return
	}
	if Ner_url == "" {
		io.WriteString(w,`{"state":"new tag is null"}`)
		return
	}
	new_tag,err:=strconv.Atoi(Ner_url)
	if err!=nil{
		io.WriteString(w, formatError(err))
		return
	}
	if new_tag<0||new_tag>65535{
		io.WriteString(w,`{"state":"new tag invalid"}`)
		return
	}
	hexs,err:=kepdb.ReadHash(act)
	if err!=nil{
		io.WriteString(w, formatError(err))
		return
	}
	files,err:=kepdb.FindALLFile(act + ".mdb")
	if err!=nil{
		io.WriteString(w, formatError(err))
		return
	}
	
	hex_len:=len(hexs)
	if len(hexs) < 64 {
		io.WriteString(w,`{"state":"data < 64"}`)
		return
	}
	hexs[hex_len-3]= byte((new_tag>>8)&255)
	hexs[hex_len-2]= byte(new_tag&255)
	
	err = os.WriteFile(files, hexs, 0644)
	
	if err!=nil{
		io.WriteString(w, formatError(err))
		return
	}
	
	post_tag.TagID=uint16(new_tag)
	post_tag.Replies[0].Tag=post_tag.TagID
	io.WriteString(w,`{"state":"OK"}`)
}
case "top":{
	//置顶
	if act=="del"{
		top_post=PostIndexView{}
		io.WriteString(w,`{"state":"del-top: OK"}`)
		return
	}
	post_top,ok:=dbStore.Load(act)
	if !ok {
		io.WriteString(w,`{"state":"set-top: post not found"}`)
		return
	}
	top_post=PostIndexView{
			Hex: post_top.PostHex,
        }
	io.WriteString(w,`{"state":"set-top: OK"}`)
}
case "delmsg":{
	del_ok:=false
	is_root:=false
	nowV,ok:=二维指针.Load(act)
	if ok {
		if nowV.Y==0{
	_,ok=dbStore.Load(nowV.X)
	if ok {dbStore.Delete(nowV.X);del_ok=true;}
	is_root=true
		}else{
	post,ok:=dbStore.Load(nowV.X)
	if ok {
		del_ok=true;
		if len(post.Replies)>nowV.Y{
			post.Replies[nowV.Y].Post="[user delete]"
		}
	}
		}
		
		if del_ok {
		path,err:=kepdb.FindALLFile(act + ".mdb")
		if err!=nil {
			logErr.Println("del post err:",err)
		}else{
			os.Remove(path)
			if is_root {
				path2,err:=kepdb.FindFile(act + ".txt")
				if err!=nil {
					logErr.Println("del idx err:",err)
				}else{
					subs,err:=kepdb.ReadSub(act)
					if err ==nil {
						for _,sub := range subs {
							sub_path,err:=kepdb.FindALLFile(sub + ".mdb")
							if err != nil {
								logErr.Println("del sub err:",err)
							}else{
								os.Remove(sub_path)
							}
						}
					}
					os.Remove(path2)
				}
			}
		}
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
	url := "http://127.222.1.16:"+token_urlPort+"/local/api/interface?svc=neighbor&req=set&key="+url.QueryEscape(act)+"&token="+token_UrlApi+"&url="+url.QueryEscape(Ner_url)+"&rpm="+strconv.Itoa(user.RPM)
	resp, err := http.Get(url)
	if err != nil {
		io.WriteString(w, formatError(err))
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		io.WriteString(w, formatError(err))
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
		io.WriteString(w, formatError(err))
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		io.WriteString(w, formatError(err))
		return
	}
	io.WriteString(w,`{"state":"`+string(body)+`"}`)
}
default:{
    io.WriteString(w,`{"state":"not found"}`)
}}
}

func topicpage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.Write(fileIndex)
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
		info:=val.(*user.UserInfo)

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
			
			if !strings.HasPrefix(nonce,post_prefix+"_"+info.Nonce) {
				w.Write([]byte("post format err"))
                return
			}

            if !addNonce(nonce) {
                w.Write([]byte("duplicate"))
                return
            }
			
			if point_to == "" {
				limitNum:=limit.GetLimit("topic:"+info.Name)
				if limitNum > 10 {
					w.Write([]byte("topic rate limit exceeded"))
					return
				}
			} else {
				limitNum:=limit.GetLimit("chge:"+info.Name)
				if limitNum > 50 {
					w.Write([]byte("change rate limit exceeded"))
					return
				}
			}

			err=sendNewPost(markdown,tagn,typeidn,point_to,point_to_root,info)
			if err!=nil {
				w.Write([]byte("send msg err"))
				return
			}

            w.Write([]byte("post ok"))
            return
        }

        if manager == "newpost" {

            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            w.Write(fileNewPost)
            return

        } else if manager == "banuser" {
			if !info.Is_admin {
				w.WriteHeader(403)
				w.Write([]byte("access deny"))
				return
			}
			state:=sql.GetByID("is_admin",info.ID)
			if state!="admin"{
				w.WriteHeader(403)
				w.Write([]byte("access deny"))
				return
			}
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
	hex := query.Get("topic")
	if IsHex(hex) {
		http.Redirect(w, r, "/t/topic/"+hex, http.StatusFound)
		return
	}
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.Write(fileIndex)
}

func viewpage(topic string) error {
	postKey, err := strconv.ParseUint(topic[:16], 16, 64)
	if err!=nil{
		return err
	}
	var now_view *int64
	val,ok:=pageViews.Load(postKey)
	if ok {
		now_view=val.(*int64)
	} else {
		var num int64
		v, _ := pageViews.LoadOrStore(postKey, &num)
		now_view = v.(*int64)
	}
	atomic.AddInt64(now_view, 1)
	return nil
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

func sendNewPost(txt string,tag,typeid int,point_to,point_to_root string,uinfo *user.UserInfo) error {
	var req ReplyRequest
	req.PostPayload=txt
	req.Tag = tag
	req.TypeID = typeid
	req.Point_to=point_to+point_to_root
        
	hash,err:=async_send(req,uinfo)
	if err!=nil||hash == "" {
		if err==nil {err=os.ErrNotExist;}
		logErr.Println("send msg err:",err)
		return err
	}
	timestamp:=int64(time.Now().Unix())
	var newRly = []postcodec.Reply{{ID: 1, User: uinfo.Name, Meta: "", Me: true, Post: string(txt), Time: timestamp, FirstTime: timestamp, Tag: uint16(req.Tag), Hex: hash},}
	
if req.Tag == 65534 {
	NowV,ok:=二维指针.Load(point_to)
	if !ok {
		return os.ErrNotExist
	}
	o_post,ok:=dbStore.Load(NowV.X)
	if ok {
		if NowV.Y==0{
		if o_post.Owner == uinfo.Name{
		o_tag:=o_post.Replies[0].Tag
		o_time:=o_post.Replies[0].FirstTime
		o_post.TypeID=byte(typeid & 255)
		meta_data:=o_post.Replies[0].Meta
		o_post.Replies[0]=postcodec.Reply{ID: 1, User: uinfo.Name, Meta: meta_data, Me: true, Post: string(txt), Time: timestamp, FirstTime: o_time, Tag: o_tag, Hex: point_to}
		}}else{
			if len(o_post.Replies)>NowV.Y{
		o_tag:=o_post.Replies[NowV.Y].Tag
		o_time:=o_post.Replies[NowV.Y].FirstTime
		meta_data:=o_post.Replies[NowV.Y].Meta
		o_post.Replies[NowV.Y]=postcodec.Reply{ID: NowV.Y+1, User: uinfo.Name, Meta: meta_data, Me: true, Post: string(txt), Time: timestamp, FirstTime: o_time, Tag: o_tag, Hex: point_to}
			}
		}
	}
}else{
	dbStore.Store(hash,&postcodec.Post{
        PostHex: hash,
        TagID:   uint16(tag),
        Owner:   uinfo.Name,
        LastTime: timestamp,
        Replies: newRly,
		TypeID: byte(typeid & 255),
	})
	newV:=mapvec.Map向量{
		X: hash,
		Y: 0,
	}
	二维指针.Store(hash,newV)
}
	sortList[sortIdx]=hash
	sortIdx++
	newList[newIdx]=hash
	newIdx++
	return nil
}

func autoSave(self string){
	file1:=filepath.Join(self, "pageview.json")
for{
	time.Sleep(time.Second*600)
	err := savePageView(file1)
	if err!=nil{
		logInfo.Println("err: save view task:",err)
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
	post_prefix,err=randSess(5)
	if err!=nil{
		post_prefix=strconv.Itoa(int(time.Now().Unix())&0xffff)
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

func savePageView(filename string) error {
	tmp:=make(map[uint64]int64)
    pageViews.Range(func(k, v interface{}) bool {
		key:=k.(uint64)
		val:=v.(*int64)
        tmp[key]=*val
        return true
    })
	
    file, err := os.Create(filename)
    if err != nil {
		return err
    }
    err = json.NewEncoder(file).Encode(tmp)
	file.Close()
    if err != nil {
        return err
    }
	return nil
}

func loadPageView(filename string) error {
	file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
	
	tmp:=make(map[string]int64)
	
    err = json.NewDecoder(file).Decode(&tmp)
    if err != nil {
        return err
    }

    for k, v := range tmp {
        ki, err := strconv.ParseUint(k, 10, 64)
        if err != nil {
            return err
        }
		val:=v
        pageViews.Store(ki, &val)
    }
    return nil
}

func formatError(err error) string {
    msg := ""
    if err != nil {
        msg = err.Error()
    }

    b,_:= json.Marshal(struct {
        State string `json:"state"`
    }{
        State: msg,
    })

    return string(b)
}

func pbbLoad() error {
	data, err := os.ReadFile(patch_file)
    if err != nil {
		if os.IsNotExist(err) { return nil; }
        return err
    }
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        kv := strings.SplitN(line, ":", 2)
        if len(kv) != 2 {
            continue
        }
		logInfo.Println("load patch perm",kv[0])
        patch_perm[kv[0]]=struct{}{}
    }
	return nil
}

func metaoffLoad() error {
	data, err := os.ReadFile(metaoff_file)
    if err != nil {
		if os.IsNotExist(err) { return nil; }
        return err
    }
	return json.Unmarshal(data, &meta_off)
}

func removeKey(key string) error {
    data, err := os.ReadFile(patch_file)
    if err != nil {
        return err
    }
    lines := strings.Split(string(data), "\n")
    out := make([]string, 0, len(lines))
    for _, line := range lines {
        if strings.HasPrefix(line, key+":") {
            continue
        }
        out = append(out, line)
    }
    return os.WriteFile(patch_file, []byte(strings.Join(out, "\n")), 0644)
}

func changeMap(oldMap map[string]struct{},key string,setadd bool) map[string]struct{} {
	newMap := make(map[string]struct{}, len(oldMap))
	for k:=range oldMap {
		newMap[k]=struct{}{}
	}
	if setadd {
		newMap[key]=struct{}{}
	} else {
		delete(newMap,key)
	}
	return newMap
}