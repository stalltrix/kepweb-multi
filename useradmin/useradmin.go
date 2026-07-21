package useradmin

import (
	"github.com/stalltrix/kep-cli/keygen"
	"kepweb-multi/sql"
	"encoding/base64"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"errors"
)

var (
	keyfile="backupkey"
)

func SetKeyFile(file string) error {
	if file!="" {
		keyfile=file
	}
	 _, err := os.Stat(keyfile)
    if err != nil {
	if os.IsNotExist(err) {
        err = os.MkdirAll(keyfile, 0700)
        if err != nil {
            return err
        }
    } else {
        return err
	}
    }
	return nil
}

func NewUser(user,pass string) error {
	if sql.Search("name",user)>=0 {
        return os.ErrExist
	}
	if len(user)<3||len(pass)<8 {
		return errors.New("user/password too less")
	}
	mainPub, mainPriv,err:=keygen.Gen_mainkey()
	if err!=nil{
		return err
	}
	pub, priv, err:=keygen.Gen_pkey()
    if err!=nil{
		return err
	}
	
	signKey:=keygen.Sig_pkey(pub, mainPriv)
	
	err=os.WriteFile(keyfile+"/"+user+".mainkey", mainPub, 0600);
	if err!=nil{
	os.WriteFile(keyfile+"/"+user+".mainpriv", mainPriv, 0600);
	os.WriteFile(keyfile+"/"+user+".pub", pub, 0600);
	os.WriteFile(keyfile+"/"+user+".priv", priv, 0600);
	os.WriteFile(keyfile+"/"+user+".sig", signKey, 0600);
	}
	
	id:=sql.New()
	if id<0 {
        return os.ErrPermission
	}
	err=sql.Set("name",user,id)
	if err!=nil {
		return err
	}
	
	hash1:=sha256.Sum256([]byte(pass))
	
	sql.Set("passwd",hex.EncodeToString(hash1[:]),id)
	sql.Set("main_key",base64.StdEncoding.EncodeToString(mainPub),id)
	sql.Set("pub_key",base64.StdEncoding.EncodeToString(pub),id)
	sql.Set("priv_key",base64.StdEncoding.EncodeToString(priv),id)
	sql.Set("sign_key",base64.StdEncoding.EncodeToString(signKey),id)
	return sql.Set("domain","localhost",id)
}

func BanUser(user string) error {
	id:=sql.Search("name",user)
	if id<0 {
        return sql.NotFoundErr
	}
	err:=sql.Set("is_banned","1",id)
	if err!=nil {
		return err
	}
	return nil
}

func BanUserByDomain(domain string) error {
	id:=sql.Search("domain",domain)
	if id<0 {
        return sql.NotFoundErr
	}
	err:=sql.Set("is_banned","1",id)
	if err!=nil {
		return err
	}
	return nil
}

func UnBanUser(user string) error {
	id:=sql.Search("name",user)
	if id<0 {
        return sql.NotFoundErr
	}
	err:=sql.Set("is_banned","",id)
	if err!=nil {
		return err
	}
	return nil
}

func ForceResetPasswd(user,newpass string) error {
	id:=sql.Search("name",user)
	if id<0 {
        return sql.NotFoundErr
	}
	if len(newpass)<8 {
		return errors.New("user/password too less")
	}
	hash1:=sha256.Sum256([]byte(newpass))
	pwd_hash := hex.EncodeToString(hash1[:])
	
	err:=sql.Set("passwd",pwd_hash,id)
	if err!=nil {
		return err
	}
	return nil
}