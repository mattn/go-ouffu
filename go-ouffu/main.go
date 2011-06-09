package goouffu

import (
	"appengine"
	"appengine/urlfetch"
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"http"
	"io/ioutil"
	"json"
	"log"
	"os"
	"rand"
	"sort"
	"strings"
	"time"
)

const (
	reqURI      = "https://api.twitter.com/oauth/request_token"   // request token endpoint
	authURI     = "https://api.twitter.com/oauth/authorize"       // user authorization endpoint
	tokenURI    = "https://api.twitter.com/oauth/access_token"    // access token endpoint
	callbackURI = "http://go-ouffu.appspot.com/callback"          // callback URI
	resURI      = "http://api.twitter.com/1/statuses/update.json" // resource URI
)

type Consumer struct {
	Key, Secret string
}

type Token struct {
	Key    string
	Secret string
}

type TempToken struct {
	Token
}

func isEncodable(c byte) bool {
	// return false if c is an unreserved character (see RFC 3986 section 2.3)
	switch {
	case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		return false
	case c >= '0' && c <= '9':
		return false
	case c == '-' || c == '.' || c == '_' || c == '~':
		return false
	}
	return true
}

func enc(src string) (dst string) {
	// RFC3986 sec 2.3
	t := "0123456789ABCDEF"
	for _, c := range []byte(src) {
		if strings.Index("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~", string(c)) == -1 {
			dst += string(c)
		} else {
			dst += "%"
			dst += string(t[c>>4])
			dst += string(t[c&15])
		}
	}
	return
}

func (creds *Consumer) verify(client *http.Client, tmp *Token, verifier string) (token *Token, err os.Error) {
	data := map[string]string{"oauth_verifier": verifier}
	creds.sign(tmp, data, tokenURI, "POST")
	r, err := client.PostForm(tokenURI, data)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		return nil, os.NewError(r.Status)
	}
	defer r.Body.Close()

	b, _ := ioutil.ReadAll(r.Body)
	q, _ := http.ParseQuery(string(b))
	if _, ok := q["oauth_token"]; !ok {
		return nil, os.NewError("invalid request")
	}

	return &Token{q["oauth_token"][0], q["oauth_token_secret"][0]}, nil
}

func (creds *Consumer) sign(token *Token, data map[string]string, uri, httpMethod string) {
	rand.Seed(time.Nanoseconds())
	data["oauth_consumer_key"] = creds.Key
	data["oauth_nonce"] = fmt.Sprintf("%d_%d", time.Seconds(), rand.Int())
	data["oauth_signature_method"] = "HMAC-SHA1"
	data["oauth_timestamp"] = fmt.Sprint(time.Seconds())
	if token != nil {
		data["oauth_token"] = token.Key
	} else {
		data["oauth_token"] = ""
	}
	data["oauth_version"] = "1.0"

	var items []string
	for k, v := range data {
		items = append(items, enc(k)+"="+enc(v))
	}
	sort.SortStrings(items)
	head := httpMethod + "&" + enc(uri) + "&" + enc(strings.Join(items, "&"))
	key := enc(creds.Secret) + "&"
	if token != nil {
		key += enc(token.Secret)
	}
	hash := hmac.NewSHA1([]byte(key))
	hash.Write([]byte(head))

	var buf bytes.Buffer
	b64enc := base64.NewEncoder(base64.StdEncoding, &buf)
	b64enc.Write(hash.Sum())
	b64enc.Close()
	data["oauth_signature"] = buf.String()
}

func (creds *Consumer) request(client *http.Client) (tmp *Token, err os.Error) {
	data := map[string]string{}
	creds.sign(nil, data, reqURI, "POST")
	log.Println(data)
	r, err := client.PostForm(reqURI, data)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, _ := ioutil.ReadAll(r.Body)
	log.Println(string(b))
	q, _ := http.ParseQuery(string(b))
	if qt, ok := q["oauth_token"]; !ok || len(qt) == 0 {
		return nil, os.NewError(string(b))
	}
	return &Token{q["oauth_token"][0], q["oauth_token_secret"][0]}, nil
}

func init() {
	b, err := ioutil.ReadFile("settings.json")
	if err != nil {
		log.Fatal("could not read settings.json", err)
	}
	var m map[string]interface{}
	err = json.Unmarshal(b, &m)
	if err != nil {
		log.Fatal("could not unmarhal settings.json", err)
	}
	creds := &Consumer{m["ClientToken"].(string), m["ClientSecret"].(string)}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf8")
		b, _ := ioutil.ReadFile("index.html")
		w.Write(b)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		client := urlfetch.Client(appengine.NewContext(r))
		tmp, err := creds.request(client)
		if err != nil {
			http.Error(w, err.String(), 500)
			return
		}
		url := fmt.Sprintf("%s?oauth_token=%s&oauth_callback=%s", authURI, http.URLEscape(tmp.Key), http.URLEscape(callbackURI))
		w.Header().Set("Set-Cookie", "tmp="+http.URLEscape(tmp.Key)+"/"+http.URLEscape(tmp.Secret))
		http.Redirect(w, r, url, 302)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		client := urlfetch.Client(appengine.NewContext(r))
		v := r.FormValue("oauth_verifier")
		a := strings.Split(r.Header.Get("Cookie"), "=", -1)
		w.Header().Set("Set-Cookie", "tmp=")
		if len(a) != 2 || a[0] != "tmp" {
			http.Error(w, "invalid request", 500)
			return
		}
		a = strings.Split(a[1], "/", -1)
		if len(a) != 2 {
			http.Error(w, "invalid request", 500)
			return
		}
		ak, _ := http.URLUnescape(a[0])
		as, _ := http.URLUnescape(a[1])
		tmp := &Token{ak, as}
		token, err := creds.verify(client, tmp, v)
		if err != nil {
			http.Error(w, err.String(), 500)
			return
		}

		gouffu := []string{"ごうっふ～", "おうっふ～", "もうっふ～", "とうっふ～", "もふもっふ～"}
		data := map[string]string{"status": gouffu[rand.Int()%len(gouffu)]}
		creds.sign(token, data, resURI, "POST")
		resp, err := client.PostForm(resURI, data)
		if err != nil {
			http.Error(w, err.String(), 500)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			http.Error(w, resp.Status, 500)
			return
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.String(), 500)
			return
		}
		var m map[string]interface{}
		err = json.Unmarshal(b, &m)
		if err != nil {
			http.Error(w, err.String(), 500)
			return
		}
		screen_name := m["user"].(map[string]interface{})["screen_name"].(string)
		id_str := m["id_str"].(string)
		url := fmt.Sprintf("https://twitter.com/%s/status/%s", screen_name, id_str)
		http.Redirect(w, r, url, 302)
	})
}
