package stream

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" // RFC 6455 requires SHA-1 for the handshake accept value.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	websocketGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	defaultTicketTTL      = 30 * time.Second
	defaultConnectionTTL  = 5 * time.Minute
	defaultMaxConnections = 128
	maxTickets            = 1024
)

type HandlerOptions struct {
	ReadToken      string
	TicketTTL      time.Duration
	ConnectionTTL  time.Duration
	MaxConnections int
	Now            func() time.Time
}

type Handler struct {
	hub       *Hub
	tokenHash [sha256.Size]byte
	ticketTTL time.Duration
	now       func() time.Time

	ticketMu          sync.Mutex
	tickets           map[[sha256.Size]byte]time.Time
	connectionMu      sync.Mutex
	activeConnections int
	maxConnections    int
	connectionTTL     time.Duration
}

func NewHandler(hub *Hub, options HandlerOptions) (*Handler, error) {
	if hub == nil || len(options.ReadToken) < 24 || len(options.ReadToken) > 512 {
		return nil, errors.New("stream requires a hub and a 24-512 byte read token")
	}
	if options.TicketTTL == 0 {
		options.TicketTTL = defaultTicketTTL
	}
	if options.TicketTTL < time.Second || options.TicketTTL > time.Minute {
		return nil, errors.New("stream ticket TTL must be between one second and one minute")
	}
	if options.ConnectionTTL == 0 {
		options.ConnectionTTL = defaultConnectionTTL
	}
	if options.ConnectionTTL < time.Second || options.ConnectionTTL > time.Hour {
		return nil, errors.New("stream connection TTL must be between one second and one hour")
	}
	if options.MaxConnections == 0 {
		options.MaxConnections = defaultMaxConnections
	}
	if options.MaxConnections < 1 || options.MaxConnections > 1024 {
		return nil, errors.New("stream connection maximum must be between one and 1024")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Handler{
		hub:            hub,
		tokenHash:      sha256.Sum256([]byte(options.ReadToken)),
		ticketTTL:      options.TicketTTL,
		now:            options.Now,
		tickets:        make(map[[sha256.Size]byte]time.Time),
		maxConnections: options.MaxConnections,
		connectionTTL:  options.ConnectionTTL,
	}, nil
}

func (handler *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/stream-ticket", handler.serveTicket)
	mux.HandleFunc("GET /api/v1/stream", handler.serveStream)
	return mux
}

func (handler *Handler) serveTicket(response http.ResponseWriter, request *http.Request) {
	if !handler.authorizeBearer(request.Header.Get("Authorization")) {
		unauthorized(response)
		return
	}

	ticketBytes := make([]byte, 32)
	if _, err := rand.Read(ticketBytes); err != nil {
		http.Error(response, "ticket unavailable", http.StatusServiceUnavailable)
		return
	}
	ticket := base64.RawURLEncoding.EncodeToString(ticketBytes)
	expiry := handler.now().Add(handler.ticketTTL)
	handler.ticketMu.Lock()
	handler.pruneTicketsLocked(handler.now())
	if len(handler.tickets) >= maxTickets {
		handler.ticketMu.Unlock()
		http.Error(response, "ticket capacity reached", http.StatusServiceUnavailable)
		return
	}
	handler.tickets[sha256.Sum256([]byte(ticket))] = expiry
	handler.ticketMu.Unlock()

	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(struct {
		Ticket    string `json:"ticket"`
		ExpiresAt string `json:"expires_at"`
		StreamURL string `json:"stream_url"`
	}{ticket, expiry.Format(time.RFC3339Nano), "/api/v1/stream"})
}

func (handler *Handler) serveStream(response http.ResponseWriter, request *http.Request) {
	key, err := validateUpgrade(request)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	if !handler.authorizeBearer(request.Header.Get("Authorization")) && !handler.consumeTicket(request.URL.Query().Get("ticket")) {
		unauthorized(response)
		return
	}
	cursor, cursorSet, filter, err := parseQuery(request.URL.Query())
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	if !handler.acquireConnection() {
		http.Error(response, "stream connection capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer handler.releaseConnection()

	hijacker, ok := response.(http.Hijacker)
	if !ok {
		http.Error(response, "websocket transport unavailable", http.StatusInternalServerError)
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(handler.connectionTTL))
	if err := writeUpgrade(buffered, key); err != nil {
		return
	}
	var writeMu sync.Mutex

	initial, client, resync := handler.hub.subscribe(cursor, cursorSet, filter)
	if resync != nil {
		_ = writeJSONFrame(connection, &writeMu, *resync)
		_ = writeCloseFrame(connection, &writeMu, 1000, "resync required")
		return
	}
	defer handler.hub.unsubscribe(client)
	for _, message := range initial {
		if err := writeJSONFrame(connection, &writeMu, message); err != nil {
			return
		}
	}

	done := make(chan struct{})
	go func() {
		readClientFrames(connection, &writeMu)
		close(done)
	}()
	connectionTimer := time.NewTimer(handler.connectionTTL)
	defer connectionTimer.Stop()
	for {
		select {
		case <-client.overflow:
			message := handler.hub.resync("slow_client", cursor)
			_ = writeJSONFrame(connection, &writeMu, message)
			_ = writeCloseFrame(connection, &writeMu, 1008, "resync required")
			return
		default:
		}
		select {
		case <-client.overflow:
			message := handler.hub.resync("slow_client", cursor)
			_ = writeJSONFrame(connection, &writeMu, message)
			_ = writeCloseFrame(connection, &writeMu, 1008, "resync required")
			return
		case <-done:
			return
		case <-handler.hub.done:
			_ = writeCloseFrame(connection, &writeMu, 1001, "server shutdown")
			return
		case <-connectionTimer.C:
			_ = writeCloseFrame(connection, &writeMu, 1001, "connection lifetime reached")
			return
		case message := <-client.messages:
			if err := writeJSONFrame(connection, &writeMu, message); err != nil {
				return
			}
			cursor, _ = strconv.ParseUint(message.ResumeCursor, 10, 64)
		}
	}
}

func (handler *Handler) acquireConnection() bool {
	handler.connectionMu.Lock()
	defer handler.connectionMu.Unlock()
	if handler.activeConnections >= handler.maxConnections {
		return false
	}
	handler.activeConnections++
	return true
}

func (handler *Handler) releaseConnection() {
	handler.connectionMu.Lock()
	handler.activeConnections--
	handler.connectionMu.Unlock()
}

func (handler *Handler) authorizeBearer(header string) bool {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(digest[:], handler.tokenHash[:]) == 1
}

func (handler *Handler) consumeTicket(ticket string) bool {
	if len(ticket) < 32 || len(ticket) > 128 || strings.ContainsAny(ticket, " \t\r\n") {
		return false
	}
	hash := sha256.Sum256([]byte(ticket))
	now := handler.now()
	handler.ticketMu.Lock()
	defer handler.ticketMu.Unlock()
	handler.pruneTicketsLocked(now)
	expiry, ok := handler.tickets[hash]
	delete(handler.tickets, hash)
	return ok && now.Before(expiry)
}

func (handler *Handler) pruneTicketsLocked(now time.Time) {
	for hash, expiry := range handler.tickets {
		if !now.Before(expiry) {
			delete(handler.tickets, hash)
		}
	}
}

func validateUpgrade(request *http.Request) (string, error) {
	if !headerHasToken(request.Header.Values("Connection"), "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") {
		return "", errors.New("websocket upgrade required")
	}
	if request.Header.Get("Sec-WebSocket-Version") != "13" {
		return "", errors.New("unsupported websocket version")
	}
	key := strings.TrimSpace(request.Header.Get("Sec-WebSocket-Key"))
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 {
		return "", errors.New("invalid websocket key")
	}
	return key, nil
}

func headerHasToken(values []string, wanted string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), wanted) {
				return true
			}
		}
	}
	return false
}

func parseQuery(query url.Values) (uint64, bool, Filter, error) {
	allowed := map[string]bool{"cursor": true, "run_id": true, "severity": true, "event_type": true, "include_audit": true, "ticket": true}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return 0, false, Filter{}, errors.New("invalid stream query")
		}
	}
	filter := Filter{RunID: query.Get("run_id"), Severity: query.Get("severity"), EventType: query.Get("event_type"), IncludeAudit: true}
	if len(filter.RunID) > 128 || len(filter.Severity) > 32 || len(filter.EventType) > 64 {
		return 0, false, Filter{}, errors.New("stream filter is too long")
	}
	if raw := query.Get("include_audit"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return 0, false, Filter{}, errors.New("invalid include_audit filter")
		}
		filter.IncludeAudit = value
	}
	rawCursor, cursorSet := query["cursor"]
	if !cursorSet {
		return 0, false, filter, nil
	}
	cursor, err := strconv.ParseUint(rawCursor[0], 10, 64)
	if err != nil {
		return 0, false, Filter{}, errors.New("invalid resume cursor")
	}
	return cursor, true, filter, nil
}

func writeUpgrade(writer *bufio.ReadWriter, key string) error {
	digest := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(digest[:])
	if _, err := fmt.Fprintf(writer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return err
	}
	return writer.Flush()
}

func writeJSONFrame(connection net.Conn, writeMu *sync.Mutex, message Message) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	_ = connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return writeFrame(connection, 0x1, payload)
}

func writeCloseFrame(connection net.Conn, writeMu *sync.Mutex, code uint16, reason string) error {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	copy(payload[2:], reason)
	writeMu.Lock()
	defer writeMu.Unlock()
	_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
	return writeFrame(connection, 0x8, payload)
}

func writeFrame(writer io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		length := make([]byte, 8)
		binary.BigEndian.PutUint64(length, uint64(len(payload)))
		header = append(header, 127)
		header = append(header, length...)
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func readClientFrames(connection net.Conn, writeMu *sync.Mutex) {
	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(connection, header); err != nil {
			return
		}
		if header[0]&0x80 == 0 || header[1]&0x80 == 0 {
			return
		}
		opcode := header[0] & 0x0f
		if opcode != 0x8 && opcode != 0x9 && opcode != 0xA {
			return
		}
		length := uint64(header[1] & 0x7f)
		if length == 126 {
			var value uint16
			if err := binary.Read(connection, binary.BigEndian, &value); err != nil {
				return
			}
			length = uint64(value)
		} else if length == 127 {
			if err := binary.Read(connection, binary.BigEndian, &length); err != nil || length&(uint64(1)<<63) != 0 {
				return
			}
		}
		if length > 125 {
			return
		}
		mask := make([]byte, 4)
		if _, err := io.ReadFull(connection, mask); err != nil {
			return
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(connection, payload); err != nil {
			return
		}
		for index := range payload {
			payload[index] ^= mask[index%4]
		}
		if opcode == 0x8 {
			return
		}
		if opcode == 0x9 {
			writeMu.Lock()
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			err := writeFrame(connection, 0xA, payload)
			writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func unauthorized(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(response, "unauthorized", http.StatusUnauthorized)
}
