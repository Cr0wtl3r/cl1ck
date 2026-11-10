package serve

import (
	"fmt"
	"net"
	"net/http"
)

type Server struct {
	ln  net.Listener
	srv *http.Server
	url string
}

func Start(html []byte) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on loopback: %w", err)
	}
	s := &Server{
		ln:  ln,
		srv: &http.Server{},
		url: "http://" + ln.Addr().String() + "/",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(html)
	})
	s.srv.Handler = mux
	go s.srv.Serve(ln)
	return s, nil
}

func (s *Server) URL() string { return s.url }

func (s *Server) Close() error { return s.srv.Close() }
