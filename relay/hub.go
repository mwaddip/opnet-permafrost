package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

// Msg is the top-level wire protocol message.
// IMPORTANT: Do NOT use omitempty on int fields — party 0 and to=0 are valid values.
type Msg struct {
	Type      string         `json:"type"`
	Parties   int            `json:"parties,omitempty"`
	Threshold int            `json:"threshold,omitempty"`
	Pubkey    string         `json:"pubkey,omitempty"`
	Session   string         `json:"session,omitempty"`
	Token     string         `json:"token,omitempty"`
	To        *int           `json:"to,omitempty"`
	From      *int           `json:"from,omitempty"`
	Payload   string         `json:"payload,omitempty"`
	PartyID   *int           `json:"partyId,omitempty"`
	Count     *int           `json:"count,omitempty"`
	Total     *int           `json:"total,omitempty"`
	URL       string         `json:"url,omitempty"`
	Pubkeys   map[int]string `json:"pubkeys,omitempty"`
	Message   string         `json:"message,omitempty"`
}

// intPtr returns a pointer to an int (for Msg fields).
func intPtr(i int) *int { return &i }

// Hub manages all sessions, WebSocket connections, and message routing.
type Hub struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	limits   *Limits
	baseURL  string
}

// handleCreate validates params, generates a session code, creates the session,
// adds party 0, and sends a "created" response.
func (h *Hub) handleCreate(conn *websocket.Conn, msg Msg) (*Session, int) {
	if msg.Parties < 2 {
		h.sendError(conn, "parties must be >= 2")
		return nil, -1
	}
	if msg.Threshold < 1 || msg.Threshold > msg.Parties {
		h.sendError(conn, "threshold must be >= 1 and <= parties")
		return nil, -1
	}
	if msg.Pubkey == "" {
		h.sendError(conn, "pubkey is required")
		return nil, -1
	}
	if msg.Parties > h.limits.MaxParties {
		h.sendError(conn, "too many parties")
		return nil, -1
	}

	h.mu.Lock()
	if len(h.sessions) >= h.limits.MaxSessions {
		h.mu.Unlock()
		h.sendError(conn, "server at capacity")
		return nil, -1
	}

	var code string
	for i := 0; i < 10; i++ {
		code = generateCode()
		if _, exists := h.sessions[code]; !exists {
			break
		}
		if i == 9 {
			h.mu.Unlock()
			h.sendError(conn, "failed to generate unique session code")
			return nil, -1
		}
	}

	sess := NewSession(code, msg.Parties, msg.Threshold, h.baseURL)
	h.sessions[code] = sess
	h.mu.Unlock()

	partyID, token, _ := sess.AddParty(msg.Pubkey, conn)

	url := ""
	if h.baseURL != "" {
		url = h.baseURL + "?session=" + code
	}

	h.sendTo(sess.GetParty(partyID), Msg{
		Type:    "created",
		Session: code,
		Token:   token,
		PartyID: intPtr(partyID),
		URL:     url,
	})

	return sess, partyID
}

// handleJoin looks up a session by code, validates it, adds the joining party,
// sends a personal "joined" response, and broadcasts to others. If now full,
// transitions to "ready" and broadcasts the ready message with all pubkeys.
func (h *Hub) handleJoin(conn *websocket.Conn, msg Msg) (*Session, int) {
	if msg.Session == "" {
		h.sendError(conn, "session code is required")
		return nil, -1
	}
	if msg.Pubkey == "" {
		h.sendError(conn, "pubkey is required")
		return nil, -1
	}

	h.mu.RLock()
	sess, exists := h.sessions[msg.Session]
	h.mu.RUnlock()

	if !exists {
		h.sendError(conn, "session not found")
		return nil, -1
	}

	sess.mu.RLock()
	full := len(sess.PartyList) >= sess.Parties
	started := sess.State == "ready"
	sess.mu.RUnlock()

	if full {
		h.sendError(conn, "session is full")
		return nil, -1
	}
	if started {
		h.sendError(conn, "session already started")
		return nil, -1
	}

	partyID, token, nowFull := sess.AddParty(msg.Pubkey, conn)
	if partyID == -1 {
		h.sendError(conn, "session is full")
		return nil, -1
	}

	// Send personal joined message to the joiner
	h.sendTo(sess.GetParty(partyID), Msg{
		Type:    "joined",
		Session: msg.Session,
		Token:   token,
		PartyID: intPtr(partyID),
		Count:   intPtr(sess.PartyCount()),
		Total:   intPtr(sess.Parties),
	})

	// Broadcast to others that someone joined
	h.broadcast(sess, Msg{
		Type:    "joined",
		PartyID: intPtr(partyID),
		Pubkey:  msg.Pubkey,
		Count:   intPtr(sess.PartyCount()),
		Total:   intPtr(sess.Parties),
	}, partyID)

	// If this addition made the session full, broadcast ready
	// (state transition was already done atomically inside AddParty)
	if nowFull {
		h.broadcast(sess, Msg{
			Type:      "ready",
			Pubkeys:   sess.Pubkeys(),
			Threshold: sess.Threshold,
		}, -1)
	}

	return sess, partyID
}

// handleReconnect looks up the session, finds the party by token,
// re-associates the connection, and broadcasts "reconnected".
func (h *Hub) handleReconnect(conn *websocket.Conn, msg Msg) (*Session, int) {
	if msg.Session == "" {
		h.sendError(conn, "session code is required")
		return nil, -1
	}
	if msg.Token == "" {
		h.sendError(conn, "token is required")
		return nil, -1
	}

	h.mu.RLock()
	sess, exists := h.sessions[msg.Session]
	h.mu.RUnlock()

	if !exists {
		h.sendError(conn, "session not found")
		return nil, -1
	}

	party := sess.GetPartyByToken(msg.Token)
	if party == nil {
		h.sendError(conn, "invalid token")
		return nil, -1
	}

	party.mu.Lock()
	party.Conn = conn
	party.Connected = true
	party.mu.Unlock()

	sess.mu.Lock()
	sess.LastActivity = time.Now()
	sess.mu.Unlock()

	// Send personal acknowledgment to the reconnecting party
	h.sendTo(party, Msg{
		Type:    "reconnected",
		PartyID: intPtr(party.ID),
		Session: msg.Session,
	})

	// Broadcast to others
	h.broadcast(sess, Msg{
		Type:    "reconnected",
		PartyID: intPtr(party.ID),
	}, party.ID)

	return sess, party.ID
}

// handleRelay validates the relay message and forwards it to the target party.
func (h *Hub) handleRelay(conn *websocket.Conn, msg Msg, senderPartyID int, sess *Session) {
	if msg.To == nil {
		h.sendError(conn, "to is required")
		return
	}
	if *msg.To == senderPartyID {
		h.sendError(conn, "cannot relay to self")
		return
	}

	target := sess.GetParty(*msg.To)
	if target == nil {
		h.sendError(conn, "target party not found")
		return
	}

	target.mu.Lock()
	targetConnected := target.Connected
	targetHasConn := target.Conn != nil
	target.mu.Unlock()

	payloadLen := len(msg.Payload)
	log.Printf("[relay] party %d → party %d (%d bytes) connected=%v hasConn=%v",
		senderPartyID, *msg.To, payloadLen, targetConnected, targetHasConn)

	sess.mu.Lock()
	sess.LastActivity = time.Now()
	sess.mu.Unlock()

	h.sendTo(target, Msg{
		Type:    "relay",
		From:    intPtr(senderPartyID),
		To:      msg.To,
		Payload: msg.Payload,
	})
}

// broadcast sends a message to all connected parties in the session,
// excluding the party with the given ID. Use exclude=-1 to send to all.
func (h *Hub) broadcast(sess *Session, msg Msg, exclude int) {
	sess.mu.RLock()
	parties := make([]*Party, len(sess.PartyList))
	copy(parties, sess.PartyList)
	sess.mu.RUnlock()

	for _, p := range parties {
		if p.ID == exclude {
			continue
		}
		p.mu.Lock()
		connected := p.Connected
		p.mu.Unlock()
		if connected {
			h.sendTo(p, msg)
		}
	}
}

// sendTo JSON-encodes a message and writes it to the party's WebSocket connection.
func (h *Hub) sendTo(p *Party, msg Msg) {
	p.mu.Lock()
	conn := p.Conn
	connected := p.Connected
	p.mu.Unlock()

	if conn == nil || !connected {
		log.Printf("[sendTo] dropped msg to party %d: conn=%v connected=%v", p.ID, conn != nil, connected)
		return
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("marshal error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		log.Printf("write error party %d: %v", p.ID, err)
	}
}

// sendError sends an error message directly on a connection (before party assignment).
func (h *Hub) sendError(conn *websocket.Conn, message string) {
	data, err := json.Marshal(Msg{
		Type:    "error",
		Message: message,
	})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn.Write(ctx, websocket.MessageText, data)
}

// cleanup runs every 60s, removing sessions with no connected parties
// and LastActivity older than the abandon timeout.
func (h *Hub) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		h.mu.Lock()
		now := time.Now()
		for code, sess := range h.sessions {
			sess.mu.RLock()
			lastActivity := sess.LastActivity
			sess.mu.RUnlock()
			if !sess.HasConnected() && now.Sub(lastActivity) > h.limits.AbandonTimeout {
				log.Printf("cleaning up abandoned session %s", code)
				delete(h.sessions, code)
			}
		}
		h.mu.Unlock()
	}
}

// handleWS is the HTTP handler that upgrades to WebSocket and manages
// the connection lifecycle: read loop, ping loop, and disconnect handling.
func (h *Hub) handleWS(w http.ResponseWriter, r *http.Request) {
	// Extract client IP for rate limiting
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	if !h.limits.AddIP(ip) {
		http.Error(w, "too many connections from this IP", http.StatusTooManyRequests)
		return
	}

	// InsecureSkipVerify disables Origin checking — relay accepts connections from
	// any origin. Security relies on E2E encryption, not origin restriction.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		h.limits.RemoveIP(ip)
		log.Printf("accept error: %v", err)
		return
	}

	conn.SetReadLimit(int64(h.limits.MaxMessageBytes))

	defer func() {
		h.limits.RemoveIP(ip)
		conn.Close(websocket.StatusNormalClosure, "")
	}()

	// Ping loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ticker := time.NewTicker(h.limits.PingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(ctx, 10*time.Second)
				if err := conn.Ping(pingCtx); err != nil {
					pingCancel()
					cancel()
					return
				}
				pingCancel()
			}
		}
	}()

	var sess *Session
	var partyID int = -1

	// On disconnect, mark party as disconnected and broadcast "left"
	defer func() {
		if sess != nil && partyID >= 0 {
			party := sess.GetParty(partyID)
			if party != nil {
				party.mu.Lock()
				party.Connected = false
				party.Conn = nil
				party.mu.Unlock()

				h.broadcast(sess, Msg{
					Type:    "left",
					PartyID: intPtr(partyID),
				}, partyID)
			}
		}
	}()

	// Read loop
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}

		var msg Msg
		if err := json.Unmarshal(data, &msg); err != nil {
			h.sendError(conn, "invalid JSON")
			continue
		}

		switch msg.Type {
		case "create":
			if sess != nil {
				h.sendError(conn, "already in a session")
				continue
			}
			s, pid := h.handleCreate(conn, msg)
			if s != nil {
				sess = s
				partyID = pid
			}

		case "join":
			if sess != nil {
				h.sendError(conn, "already in a session")
				continue
			}
			s, pid := h.handleJoin(conn, msg)
			if s != nil {
				sess = s
				partyID = pid
			}

		case "reconnect":
			if sess != nil {
				h.sendError(conn, "already in a session")
				continue
			}
			s, pid := h.handleReconnect(conn, msg)
			if s != nil {
				sess = s
				partyID = pid
			}

		case "relay":
			if sess == nil || partyID < 0 {
				h.sendError(conn, "not in a session")
				continue
			}
			h.handleRelay(conn, msg, partyID, sess)

		default:
			h.sendError(conn, "unknown message type")
		}
	}
}
