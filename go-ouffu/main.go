package goouffu

import (
	"appengine"
	"appengine/urlfetch"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
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
	Key    string
	Secret string
}

type Token struct {
	Key    string
	Secret string
}

func enc(src string) (dst string) {
	// RFC3986 sec 2.3
	t := "0123456789ABCDEF"
	for _, c := range []byte(src) {
		if strings.Index("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~", string(c)) == -1 {
			dst += "%"
			dst += string(t[c>>4])
			dst += string(t[c&15])
		} else {
			dst += string(c)
		}
	}
	return
}

func (creds *Consumer) verify(client *http.Client, tmp *Token, verifier string) (token *Token, err error) {
	data := make(url.Values)
	data.Set("oauth_verifier", verifier)
	creds.sign(tmp, data, tokenURI, "POST")
	r, err := client.PostForm(tokenURI, data)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		return nil, errors.New(r.Status)
	}
	defer r.Body.Close()

	b, _ := ioutil.ReadAll(r.Body)
	q, _ := url.ParseQuery(string(b))
	if _, ok := q["oauth_token"]; !ok {
		return nil, errors.New("invalid request")
	}

	return &Token{q["oauth_token"][0], q["oauth_token_secret"][0]}, nil
}

func (creds *Consumer) sign(token *Token, data url.Values, uri, httpMethod string) {
	rand.Seed(time.Now().Unix())
	data.Set("oauth_consumer_key", creds.Key)
	data.Set("oauth_nonce", fmt.Sprintf("%d_%d", time.Now().Unix(), rand.Int()))
	data.Set("oauth_signature_method", "HMAC-SHA1")
	data.Set("oauth_timestamp", fmt.Sprint(time.Now().Unix()))
	if token != nil {
		data.Set("oauth_token", token.Key)
	} else {
		data.Set("oauth_token", "")
	}
	data.Set("oauth_version", "1.0")

	var items []string
	for k, v := range data {
		items = append(items, enc(k)+"="+enc(v[0]))
	}
	sort.Sort(sort.StringSlice(items[0:]))
	head := httpMethod + "&" + enc(uri) + "&" + enc(strings.Join(items, "&"))
	key := enc(creds.Secret) + "&"
	if token != nil {
		key += enc(token.Secret)
	}
	hash := hmac.New(sha1.New, []byte(key))
	hash.Write([]byte(head))

	var buf bytes.Buffer
	b64enc := base64.NewEncoder(base64.StdEncoding, &buf)
	b64enc.Write(hash.Sum(nil))
	b64enc.Close()
	data.Set("oauth_signature", buf.String())
}

func (creds *Consumer) request(client *http.Client) (tmp *Token, err error) {
	data := make(url.Values)
	creds.sign(nil, data, reqURI, "POST")
	r, err := client.PostForm(reqURI, data)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, _ := ioutil.ReadAll(r.Body)
	q, _ := url.ParseQuery(string(b))
	if qt, ok := q["oauth_token"]; !ok || len(qt) == 0 {
		return nil, errors.New(string(b))
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
			http.Error(w, err.Error(), 500)
			return
		}
		uri := fmt.Sprintf("%s?oauth_token=%s&oauth_callback=%s", authURI, url.QueryEscape(tmp.Key), url.QueryEscape(callbackURI))
		w.Header().Set("Set-Cookie", "auth="+url.QueryEscape(tmp.Key)+"/"+url.QueryEscape(tmp.Secret)+"; path=/;")
		http.Redirect(w, r, uri, 302)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		client := urlfetch.Client(appengine.NewContext(r))
		v := r.FormValue("oauth_verifier")
		var c string
		for _, cookie := range r.Cookies() {
			if cookie.Name == "auth" {
				c = cookie.Value
				break
			}
		}
		if c == "" {
			http.Error(w, "invalid request", 401)
			return
		}
		a := strings.SplitN(c, "/", 2)
		w.Header().Set("Set-Cookie", "auth=")
		ak, _ := url.QueryUnescape(a[0])
		as, _ := url.QueryUnescape(a[1])
		tmp := &Token{ak, as}
		token, err := creds.verify(client, tmp, v)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		gouffu := []string{"ごうっふ～", "おうっふ～", "もうっふ～", "とうっふ～", "もふもっふ～", "わっふ～", "きゃっふ～"}
		data := make(url.Values)
		data.Set("status", gouffu[rand.Int()%len(gouffu)])
		creds.sign(token, data, resURI, "POST")
		resp, err := client.PostForm(resURI, data)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			http.Error(w, resp.Status, 500)
			return
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var m map[string]interface{}
		err = json.Unmarshal(b, &m)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		screen_name := m["user"].(map[string]interface{})["screen_name"].(string)
		id_str := m["id_str"].(string)
		url := fmt.Sprintf("https://twitter.com/%s/status/%s", screen_name, id_str)
		http.Redirect(w, r, url, 302)
	})
}
