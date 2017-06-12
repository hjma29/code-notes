HTTP Server

type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, req).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, req *Request) {
    f(w, req)
}

func ArgServer(w http.ResponseWriter, req *http.Request) {
    fmt.Fprintln(w, os.Args)
}

http.Handle("/args", http.HandlerFunc(ArgServer))

================
func main() {
		http.HandleFunc("/", handler) // each request calls handler
		log.Fatal(http.ListenAndServe("localhost:8000", nil))
	}


	// handler echoes the Path component of the requested URL.
	func handler(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "URL.Path = %q\n", r.URL.Path)
	}

===============
func HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

func Handle(pattern string, handler Handler) { DefaultServeMux.Handle(pattern, handler) }
  
var DefaultServeMux = &defaultServeMux
var defaultServeMux ServeMux

type ServeMux struct {
    mu    sync.RWMutex
    m     map[string]muxEntry
    hosts bool // whether any patterns contain hostnames
}


// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
    mux.mu.Lock()
    defer mux.mu.Unlock()

    if pattern == "" {
        panic("http: invalid pattern " + pattern)
    }
    if handler == nil {
        panic("http: nil handler")
    }
    if mux.m[pattern].explicit {
        panic("http: multiple registrations for " + pattern)
    }

    if mux.m == nil {
        mux.m = make(map[string]muxEntry)
    }
    mux.m[pattern] = muxEntry{explicit: true, h: handler, pattern: pattern}

    if pattern[0] != '/' {
        mux.hosts = true
    }

    // Helpful behavior:
    // If pattern is /tree/, insert an implicit permanent redirect for /tree.
    // It can be overridden by an explicit registration.
    n := len(pattern)
    if n > 0 && pattern[n-1] == '/' && !mux.m[pattern[0:n-1]].explicit {
        // If pattern contains a host name, strip it and use remaining
        // path for redirect.
        path := pattern
        if pattern[0] != '/' {
            // In pattern, at least the last character is a '/', so
            // strings.Index can't be -1.
            path = pattern[strings.Index(pattern, "/"):]
        }
        url := &url.URL{Path: path}
        mux.m[pattern[0:n-1]] = muxEntry{h: RedirectHandler(url.String(), StatusMovedPermanently), pattern: pattern}
    }
}

===============
func ListenAndServe(addr string, handler Handler) error {
    server := &Server{Addr: addr, Handler: handler}
    return server.ListenAndServe()
}
type Handler interface {
	ServeHTTP(ResponseWriter, *Request)
}

func (srv *Server) ListenAndServe() error {
    addr := srv.Addr
    if addr == "" {
        addr = ":http"
    }
    ln, err := net.Listen("tcp", addr)
    if err != nil {
        return err
    }
    return srv.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
}
func (srv *Server) Serve(l net.Listener) error {
    defer l.Close()
    if fn := testHookServerServe; fn != nil {
        fn(srv, l)
    }
    var tempDelay time.Duration // how long to sleep on accept failure

    if err := srv.setupHTTP2_Serve(); err != nil {
        return err
    }

    srv.trackListener(l, true)
    defer srv.trackListener(l, false)

    baseCtx := context.Background() // base is always background, per Issue 16220
    ctx := context.WithValue(baseCtx, ServerContextKey, srv)
    ctx = context.WithValue(ctx, LocalAddrContextKey, l.Addr())
    for {
        rw, e := l.Accept()
        if e != nil {
            select {
            case <-srv.getDoneChan():
                return ErrServerClosed
            default:
            }
            if ne, ok := e.(net.Error); ok && ne.Temporary() {
                if tempDelay == 0 {
                    tempDelay = 5 * time.Millisecond
                } else {
                    tempDelay *= 2
                }
                if max := 1 * time.Second; tempDelay > max {
                    tempDelay = max
                }
                srv.logf("http: Accept error: %v; retrying in %v", e, tempDelay)
                time.Sleep(tempDelay)
                continue
            }
            return e
        }
        tempDelay = 0
        c := srv.newConn(rw)
        c.setState(c.rwc, StateNew) // before Serve can return
        go c.serve(ctx)
    }
}
func (c *conn) serve(ctx context.Context) {
    c.remoteAddr = c.rwc.RemoteAddr().String()
    defer func() {
        if err := recover(); err != nil && err != ErrAbortHandler {
            const size = 64 << 10
            buf := make([]byte, size)
            buf = buf[:runtime.Stack(buf, false)]
            c.server.logf("http: panic serving %v: %v\n%s", c.remoteAddr, err, buf)
        }
        if !c.hijacked() {
            c.close()
            c.setState(c.rwc, StateClosed)
        }
    }()

    if tlsConn, ok := c.rwc.(*tls.Conn); ok {
        if d := c.server.ReadTimeout; d != 0 {
            c.rwc.SetReadDeadline(time.Now().Add(d))
        }
        if d := c.server.WriteTimeout; d != 0 {
            c.rwc.SetWriteDeadline(time.Now().Add(d))
        }
        if err := tlsConn.Handshake(); err != nil {
            c.server.logf("http: TLS handshake error from %s: %v", c.rwc.RemoteAddr(), err)
            return
        }
        c.tlsState = new(tls.ConnectionState)
        *c.tlsState = tlsConn.ConnectionState()
        if proto := c.tlsState.NegotiatedProtocol; validNPN(proto) {
            if fn := c.server.TLSNextProto[proto]; fn != nil {
                h := initNPNRequest{tlsConn, serverHandler{c.server}}
                fn(c.server, tlsConn, h)
            }
            return
        }
    }

    // HTTP/1.x from here on.

    ctx, cancelCtx := context.WithCancel(ctx)
    c.cancelCtx = cancelCtx
    defer cancelCtx()

    c.r = &connReader{conn: c}
    c.bufr = newBufioReader(c.r)
    c.bufw = newBufioWriterSize(checkConnErrorWriter{c}, 4<<10)

    for {
        w, err := c.readRequest(ctx)
        if c.r.remain != c.server.initialReadLimitSize() {
            // If we read any bytes off the wire, we're active.
            c.setState(c.rwc, StateActive)
        }
        if err != nil {
            const errorHeaders = "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

            if err == errTooLarge {
                // Their HTTP client may or may not be
                // able to read this if we're
                // responding to them and hanging up
                // while they're still writing their
                // request. Undefined behavior.
                const publicErr = "431 Request Header Fields Too Large"
                fmt.Fprintf(c.rwc, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
                c.closeWriteAndWait()
                return
            }
            if isCommonNetReadError(err) {
                return // don't reply
            }

            publicErr := "400 Bad Request"
            if v, ok := err.(badRequestError); ok {
                publicErr = publicErr + ": " + string(v)
            }

            fmt.Fprintf(c.rwc, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
            return
        }

        // Expect 100 Continue support
        req := w.req
        if req.expectsContinue() {
            if req.ProtoAtLeast(1, 1) && req.ContentLength != 0 {
                // Wrap the Body reader with one that replies on the connection
                req.Body = &expectContinueReader{readCloser: req.Body, resp: w}
            }
        } else if req.Header.get("Expect") != "" {
            w.sendExpectationFailed()
            return
        }

        c.curReq.Store(w)

        if requestBodyRemains(req.Body) {
            registerOnHitEOF(req.Body, w.conn.r.startBackgroundRead)
        } else {
            if w.conn.bufr.Buffered() > 0 {
                w.conn.r.closeNotifyFromPipelinedRequest()
            }
            w.conn.r.startBackgroundRead()
        }

        // HTTP cannot have multiple simultaneous active requests.[*]
        // Until the server replies to this request, it can't read another,
        // so we might as well run the handler in this goroutine.
        // [*] Not strictly true: HTTP pipelining. We could let them all process
        // in parallel even if their responses need to be serialized.
        // But we're not going to implement HTTP pipelining because it
        // was never deployed in the wild and the answer is HTTP/2.
        serverHandler{c.server}.ServeHTTP(w, w.req)
        w.cancelCtx()
        if c.hijacked() {
            return
        }
        w.finishRequest()
        if !w.shouldReuseConnection() {
            if w.requestBodyLimitHit || w.closedRequestBodyEarly() {
                c.closeWriteAndWait()
            }
            return
        }
        c.setState(c.rwc, StateIdle)
        c.curReq.Store((*response)(nil))

        if !w.conn.server.doKeepAlives() {
            // We're in shutdown mode. We might've replied
            // to the user without "Connection: close" and
            // they might think they can send another
            // request, but such is life with HTTP/1.1.
            return
        }

        if d := c.server.idleTimeout(); d != 0 {
            c.rwc.SetReadDeadline(time.Now().Add(d))
            if _, err := c.bufr.Peek(4); err != nil {
                return
            }
        }
        c.rwc.SetReadDeadline(time.Time{})
    }
}


// Read next request from connection.
func (c *conn) readRequest(ctx context.Context) (w *response, err error) {
    if c.hijacked() {
        return nil, ErrHijacked
    }

    var (
        wholeReqDeadline time.Time // or zero if none
        hdrDeadline      time.Time // or zero if none
    )
    t0 := time.Now()
    if d := c.server.readHeaderTimeout(); d != 0 {
        hdrDeadline = t0.Add(d)
    }
    if d := c.server.ReadTimeout; d != 0 {
        wholeReqDeadline = t0.Add(d)
    }
    c.rwc.SetReadDeadline(hdrDeadline)
    if d := c.server.WriteTimeout; d != 0 {
        defer func() {
            c.rwc.SetWriteDeadline(time.Now().Add(d))
        }()
    }

    c.r.setReadLimit(c.server.initialReadLimitSize())
    if c.lastMethod == "POST" {
        // RFC 2616 section 4.1 tolerance for old buggy clients.
        peek, _ := c.bufr.Peek(4) // ReadRequest will get err below
        c.bufr.Discard(numLeadingCRorLF(peek))
    }
    req, err := readRequest(c.bufr, keepHostHeader)
    if err != nil {
        if c.r.hitReadLimit() {
            return nil, errTooLarge
        }
        return nil, err
    }

    if !http1ServerSupportsRequest(req) {
        return nil, badRequestError("unsupported protocol version")
    }

    c.lastMethod = req.Method
    c.r.setInfiniteReadLimit()

    hosts, haveHost := req.Header["Host"]
    isH2Upgrade := req.isH2Upgrade()
    if req.ProtoAtLeast(1, 1) && (!haveHost || len(hosts) == 0) && !isH2Upgrade {
        return nil, badRequestError("missing required Host header")
    }
    if len(hosts) > 1 {
        return nil, badRequestError("too many Host headers")
    }
    if len(hosts) == 1 && !httplex.ValidHostHeader(hosts[0]) {
        return nil, badRequestError("malformed Host header")
    }
    for k, vv := range req.Header {
        if !httplex.ValidHeaderFieldName(k) {
            return nil, badRequestError("invalid header name")
        }
        for _, v := range vv {
            if !httplex.ValidHeaderFieldValue(v) {
                return nil, badRequestError("invalid header value")
            }
        }
    }
    delete(req.Header, "Host")

    ctx, cancelCtx := context.WithCancel(ctx)
    req.ctx = ctx
    req.RemoteAddr = c.remoteAddr
    req.TLS = c.tlsState
    if body, ok := req.Body.(*body); ok {
        body.doEarlyClose = true
    }

    // Adjust the read deadline if necessary.
    if !hdrDeadline.Equal(wholeReqDeadline) {
        c.rwc.SetReadDeadline(wholeReqDeadline)
    }

    w = &response{
        conn:          c,
        cancelCtx:     cancelCtx,
        req:           req,
        reqBody:       req.Body,
        handlerHeader: make(Header),
        contentLength: -1,
        closeNotifyCh: make(chan bool, 1),

        // We populate these ahead of time so we're not
        // reading from req.Header after their Handler starts
        // and maybe mutates it (Issue 14940)
        wants10KeepAlive: req.wantsHttp10KeepAlive(),
        wantsClose:       req.wantsClose(),
    }
    if isH2Upgrade {
        w.closeAfterReply = true
    }
    w.cw.res = w
    w.w = newBufioWriterSize(&w.cw, bufferBeforeChunkingSize)
    return w, nil
}


// serverHandler delegates to either the server's Handler or
// DefaultServeMux and also handles "OPTIONS *" requests.
type serverHandler struct {
    srv *Server
}

// A conn represents the server side of an HTTP connection.
type conn struct {
    // server is the server on which the connection arrived.
    // Immutable; never nil.
    server *Server

func (sh serverHandler) ServeHTTP(rw ResponseWriter, req *Request) {
    handler := sh.srv.Handler
    if handler == nil {
        handler = DefaultServeMux
    }
    if req.RequestURI == "*" && req.Method == "OPTIONS" {
        handler = globalOptionsHandler{}
    }
    handler.ServeHTTP(rw, req)
}


