package main

import (
	"crypto/tls"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func checkUrl(url string) bool {
	flag := false
	port := strings.LastIndex(url, ":")
	if port != -1 {
		url = url[:port]
	}
	for _, v := range Config.Whitelist {
		if ok, _ := regexp.MatchString(v, url); ok {
			flag = true
			break
		}
	}
	return flag
}

func handleTunneling(w http.ResponseWriter, req *http.Request) {
	//设置超时防止大量超时导致服务器资源不大量占用
	log.Printf("tunneling proxy %v", req.RequestURI)
	if !checkUrl(req.RequestURI) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<h1>此链接不在代理白名单之内</h1>"))
		return
	}
	dest_conn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	//类型转换
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	//接管连接
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

//转发连接的数据
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	//校验白名单
	log.Printf("http proxy %v", req.RequestURI)
	if !checkUrl(req.RequestURI) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<h1>此链接不在代理白名单之内</h1>"))
		return
	}

	//roudtrip 传递发送的请求返回响应的结果
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	//把目标服务器的响应header复制
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

//复制响应头
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

type AppConfig struct {
	Proto     string
	Port      int
	PemPath   string `yaml:"pemPath"`
	KeyPath   string `yaml:"keyPath"`
	Whitelist []string
}

var Config AppConfig

func main() {
	file, _ := ioutil.ReadFile("config.yaml")
	if err := yaml.Unmarshal(file, &Config); err != nil {
		log.Fatalf("Config file read error: %v", err)
	}
	if Config.Proto != "http" && Config.Proto != "https" {
		log.Fatal("Protocol must be either http or https")
	}
	for k, v := range Config.Whitelist {
		Config.Whitelist[k] = strings.ReplaceAll(v, "/", "\\/")
		Config.Whitelist[k] = "^" + strings.ReplaceAll(v, "*", ".*") + "$"
	}
	server := &http.Server{
		Addr: ":" + strconv.Itoa(Config.Port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				//支持https websocket deng ... tcp
				handleTunneling(w, r)
			} else {
				//直接http代理
				handleHTTP(w, r)
			}
		}),
		// 关闭http2
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Printf("0.0.0.0:%v %s proxy running", Config.Port, Config.Proto)
	if Config.Proto == "http" {
		log.Fatal(server.ListenAndServe())
	} else {
		log.Fatal(server.ListenAndServeTLS(Config.PemPath, Config.KeyPath))
	}
}
