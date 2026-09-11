package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type requestCounter struct {
	mu     sync.Mutex
	total  int
	routes map[string]int
}

type stats struct {
	Total  int            `json:"total"`
	Routes map[string]int `json:"routes"`
}

type echoResponse struct {
	Method          string   `json:"method"`
	RequestURI      string   `json:"request_uri"`
	EscapedPath     string   `json:"escaped_path"`
	BodySHA256      string   `json:"body_sha256"`
	BodyLength      int      `json:"body_length"`
	MultiHeader     []string `json:"multi_header"`
	Cookie          string   `json:"cookie"`
	AuthorizationOK bool     `json:"authorization_ok"`
	ForwardedFor    []string `json:"forwarded_for"`
	ForwardedProto  []string `json:"forwarded_proto"`
	ForwardedHost   []string `json:"forwarded_host"`
	ForwardedPort   []string `json:"forwarded_port"`
}

func main() {
	counter := &requestCounter{routes: make(map[string]int)}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__e2e/healthz" && r.URL.Path != "/__e2e/stats" {
			counter.add(r.Method + " " + r.URL.Path)
		}
		switch r.URL.Path {
		case "/__e2e/healthz":
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		case "/__e2e/stats":
			writeJSON(w, http.StatusOK, counter.snapshot())
		case "/native-error":
			w.Header().Add("X-E2E-Multi", "first")
			w.Header().Add("X-E2E-Multi", "second")
			w.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(w, "native-teapot")
		case "/redirect":
			w.Header().Set("Location", "/login?from=e2e")
			http.SetCookie(w, &http.Cookie{Name: "first", Value: "one", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "second", Value: "two", Path: "/"})
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/compressed":
			compressed(w)
		case "/sse":
			streamEvents(w)
		case "/ws":
			serveWebSocket(w, r)
		default:
			echo(w, r)
		}
	})
	server := &http.Server{
		Addr:              ":8081",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("fake upstream listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (c *requestCounter) add(route string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	c.routes[route]++
}

func (c *requestCounter) snapshot() stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	routes := make(map[string]int, len(c.routes))
	for key, count := range c.routes {
		routes[key] = count
	}
	return stats{Total: c.total, Routes: routes}
}

func echo(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	digest := sha256.Sum256(body)
	writeJSON(w, http.StatusOK, echoResponse{
		Method:          r.Method,
		RequestURI:      r.RequestURI,
		EscapedPath:     r.URL.EscapedPath(),
		BodySHA256:      hex.EncodeToString(digest[:]),
		BodyLength:      len(body),
		MultiHeader:     r.Header.Values("X-E2E-Multi"),
		Cookie:          r.Header.Get("Cookie"),
		AuthorizationOK: r.Header.Get("Authorization") == "Bearer e2e-forwarded-token",
		ForwardedFor:    r.Header.Values("X-Forwarded-For"),
		ForwardedProto:  r.Header.Values("X-Forwarded-Proto"),
		ForwardedHost:   r.Header.Values("X-Forwarded-Host"),
		ForwardedPort:   r.Header.Values("X-Forwarded-Port"),
	})
}

func compressed(w http.ResponseWriter) {
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	_, _ = io.WriteString(writer, "compressed-through-guard")
	_ = writer.Close()
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Vary", "Accept-Encoding")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output.Bytes())
}

func streamEvents(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, "data: first\n\n")
	flusher.Flush()
	time.Sleep(700 * time.Millisecond)
	_, _ = io.WriteString(w, "data: second\n\n")
	flusher.Flush()
}

func serveWebSocket(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" || !headerHasToken(r.Header.Values("Connection"), "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		http.Error(w, "bad websocket handshake", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	acceptDigest := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptDigest[:])
	_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	if err := rw.Flush(); err != nil {
		return
	}
	for {
		opcode, payload, err := readFrame(rw.Reader)
		if err != nil {
			return
		}
		switch opcode {
		case 0x1:
			if err := writeFrame(rw.Writer, 0x1, payload); err != nil {
				return
			}
		case 0x8:
			_ = writeFrame(rw.Writer, 0x8, payload)
			return
		case 0x9:
			if err := writeFrame(rw.Writer, 0xA, payload); err != nil {
				return
			}
		}
	}
}

func headerHasToken(values []string, want string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func readFrame(reader *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	opcode := header[0] & 0x0f
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > 64<<10 {
		return 0, nil, errors.New("websocket frame is too large")
	}
	masked := header[1]&0x80 != 0
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%len(mask)]
		}
	}
	return opcode, payload, nil
}

func writeFrame(writer *bufio.Writer, opcode byte, payload []byte) error {
	if len(payload) > 125 {
		return errors.New("test frame is too large")
	}
	if err := writer.WriteByte(0x80 | opcode); err != nil {
		return err
	}
	if err := writer.WriteByte(byte(len(payload))); err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	return writer.Flush()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
