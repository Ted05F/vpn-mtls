// Package decoy — сайт-заглушка, который видят все, кто подключается к
// серверу без валидного клиентского сертификата (браузеры, сканеры, DPI
// с активным зондированием).
package decoy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// New возвращает обработчик-заглушку. Если upstream задан (например,
// http://caddy:80 со статическим сайтом), запросы проксируются туда;
// иначе отдаётся встроенная страница.
func New(upstream string) (http.Handler, error) {
	if upstream == "" {
		return builtin(), nil
	}
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = &http.Transport{
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
	}
	base := rp.Director
	rp.Director = func(r *http.Request) {
		base(r)
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	return rp, nil
}

func builtin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})
}

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northwind Notes</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#222}
h1{font-size:1.8rem}a{color:#0a58ca}footer{margin-top:3rem;color:#777;font-size:.9rem}</style></head>
<body><h1>Northwind Notes</h1>
<p>Personal notes on distributed systems, networking and photography.</p>
<p>New posts are on the way. In the meantime, feel free to say hello.</p>
<footer>&copy; Northwind Notes</footer></body></html>`
