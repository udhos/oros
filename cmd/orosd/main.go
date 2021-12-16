package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/caddyserver/certmagic"
)

type server struct {
	basicAuthUser string
	basicAuthPass string
	mux           *http.ServeMux
	lock          sync.RWMutex
}

func (s *server) auth(user, pass string) bool {
	s.lock.RLock()
	auth := user == s.basicAuthUser && pass == s.basicAuthPass
	s.lock.RUnlock()
	return auth
}

func main() {

	app := server{
		basicAuthUser: "admin",
		basicAuthPass: "admin",
		mux:           http.NewServeMux(),
	}

	var key, cert, listen string
	flag.StringVar(&key, "key", "key.pem", "TLS key file")
	flag.StringVar(&cert, "cert", "cert.pem", "TLS cert file")
	flag.StringVar(&listen, "listen", ":8080", "listen address")
	flag.Parse()

	registerAPI(&app, "/", serveRoot)
	registerAPI(&app, "/api", serveAPI)

	if fileExists(cert) && fileExists(key) {
		if err := listenAndServeTLS(listen, cert, key, app.mux); err != nil {
			log.Fatalf("ListenAndServeTLS: %s: %v", listen, err)
		}
		return
	}

	// use the staging endpoint while we're developing
	certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	hostname := "example.com"
	err := certmagic.HTTPS([]string{hostname}, app.mux)
	log.Fatal(err)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func listenAndServeTLS(listen, certFile, keyFile string, handler http.Handler) error {
	server := &http.Server{Addr: listen, Handler: handler}
	log.Printf("listenAndServeTLS: serving HTTPS on TCP %s", listen)
	return server.ListenAndServeTLS(certFile, keyFile)
}

func serveRoot(w http.ResponseWriter, r *http.Request, app *server) {
	notFound := "404 Nothing here"
	log.Printf("serveRoot: url=%s from=%s %s", r.URL.Path, r.RemoteAddr, notFound)
	http.Error(w, notFound, 404)
}

func serveAPI(w http.ResponseWriter, r *http.Request, app *server) {
	const me = "serveAPI"
	log.Printf("%s: url=%s from=%s", me, r.URL.Path, r.RemoteAddr)
}

type apiHandler func(w http.ResponseWriter, r *http.Request, app *server)

func registerAPI(app *server, path string, handler apiHandler) {
	log.Printf("registerAPI: registering api: %s", path)

	app.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {

		log.Printf("handler %s: url=%s from=%s", path, r.URL.Path, r.RemoteAddr)

		caller := "handler " + path + ":"

		if badBasicAuth(caller, w, r, app) {
			return
		}

		handler(w, r, app)
	})
}

func badBasicAuth(caller string, w http.ResponseWriter, r *http.Request, app *server) bool {

	username, password, authOK := r.BasicAuth()
	if !authOK {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		log.Printf("%s url=%s from=%s Basic Auth missing", caller, r.URL.Path, r.RemoteAddr)
		http.Error(w, "401 Unauthenticated", 401)
		return true
	}

	log.Printf("%s url=%s from=%s Basic Auth username=%s", caller, r.URL.Path, r.RemoteAddr, username)

	if !app.auth(username, password) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		log.Printf("%s url=%s from=%s Basic Auth failed", caller, r.URL.Path, r.RemoteAddr)
		http.Error(w, "401 Unauthenticated", 401)
		return true
	}

	log.Printf("%s url=%s from=%s Basic Auth ok", caller, r.URL.Path, r.RemoteAddr)

	return false
}
