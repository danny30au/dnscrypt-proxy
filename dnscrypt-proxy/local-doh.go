package main

import (
    "encoding/base64"
    "io"
    "net"
    "net/http"
    "sort"
    "strconv"
    "sync"
    "time"

    "codeberg.org/miekg/dns"
    "github.com/jedisct1/dlog"
)

var (
    // Pre-allocated padding buffer to avoid repeated allocations
    paddingBuffer = func() []byte {
        buf := make([]byte, MaxDNSPacketSize)
        for i := range buf {
            buf[i] = 'X'
        }
        return buf
    }()

    // Packet buffer pool for memory reuse
    packetPool = sync.Pool{
        New: func() interface{} {
            b := make([]byte, 0, MaxDNSPacketSize)
            return &b
        },
    }
)

type localDoHHandler struct {
    proxy *Proxy
}

func (handler localDoHHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
    proxy := handler.proxy
    if !proxy.clientsCountInc() {
        dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
        return
    }
    defer proxy.clientsCountDec()

    dataType := "application/dns-message"
    writer.Header().Set("Server", "dnscrypt-proxy")

    if request.URL.Path != proxy.localDoHPath {
        writer.WriteHeader(404)
        return
    }

    // Get buffer from pool
    bufPtr := packetPool.Get().(*[]byte)
    defer packetPool.Put(bufPtr)
    packet := (*bufPtr)[:0]

    var err error
    start := time.Now()

    if request.Method == "POST" && request.Header.Get("Content-Type") == dataType {
        // Read directly into buffer
        limitReader := io.LimitReader(request.Body, int64(MaxDNSPacketSize))
        packet, err = io.ReadAll(limitReader)
        if err != nil {
            dlog.Warnf("No body in a local DoH query")
            return
        }
    } else if request.Method == "GET" && request.Header.Get("Accept") == dataType {
        encodedPacket := request.URL.Query().Get("dns")
        if len(encodedPacket) >= MinDNSPacketSize*4/3 && len(encodedPacket) <= MaxDNSPacketSize*4/3 {
            packet, err = base64.RawURLEncoding.DecodeString(encodedPacket)
            if err != nil {
                dlog.Warnf("Invalid base64 in a local DoH query")
                return
            }
        }
    }

    if len(packet) < MinDNSPacketSize {
        writer.Header().Set("Content-Type", "text/plain")
        writer.WriteHeader(400)
        writer.Write([]byte("dnscrypt-proxy local DoH server\n"))
        return
    }

    clientAddr, err := net.ResolveTCPAddr("tcp", request.RemoteAddr)
    if err != nil {
        dlog.Errorf("Unable to get the client address: [%v]", err)
        return
    }

    xClientAddr := net.Addr(clientAddr)
    hasEDNS0Padding, err := hasEDNS0Padding(packet)
    if err != nil {
        writer.WriteHeader(400)
        return
    }

    response := proxy.processIncomingQuery("local_doh", proxy.xTransport.mainProto, packet, &xClientAddr, nil, start, false)
    if len(response) == 0 {
        writer.WriteHeader(500)
        return
    }

    // Calculate padding
    responseLen := len(response)
    paddedLen := dohPaddedLen(responseLen)
    padLen := paddedLen - responseLen

    if hasEDNS0Padding {
        msg := dns.Msg{Data: packet}
        if err := msg.Unpack(); err != nil {
            writer.WriteHeader(400)
            return
        }
        response, err = addEDNS0PaddingIfNoneFound(&msg, response, padLen)
        if err != nil {
            dlog.Critical(err)
            writer.WriteHeader(500)
            return
        }
    } else if padLen > 0 {
        // Use pre-allocated padding buffer
        writer.Header().Set("X-Pad", string(paddingBuffer[:padLen]))
    }

    // Set headers and write response
    writer.Header().Set("Content-Type", dataType)
    writer.Header().Set("Content-Length", strconv.Itoa(len(response)))
    writer.WriteHeader(200)
    writer.Write(response)
}

func (proxy *Proxy) localDoHListener(acceptPc *net.TCPListener) {
    defer acceptPc.Close()
    if len(proxy.localDoHCertFile) == 0 || len(proxy.localDoHCertKeyFile) == 0 {
        dlog.Fatal("A certificate and a key are required to start a local DoH service")
    }

    httpServer := &http.Server{
        ReadTimeout:       proxy.timeout,
        WriteTimeout:      proxy.timeout,
        IdleTimeout:       120 * time.Second,
        MaxHeaderBytes:    4096,
        ReadHeaderTimeout: 5 * time.Second,
        Handler:           localDoHHandler{proxy: proxy},
    }

    httpServer.SetKeepAlivesEnabled(true)

    if err := httpServer.ServeTLS(acceptPc, proxy.localDoHCertFile, proxy.localDoHCertKeyFile); err != nil {
        dlog.Fatal(err)
    }
}

func dohPaddedLen(unpaddedLen int) int {
    // Optimized with binary search instead of linear iteration
    boundaries := [17]int{
        64, 128, 192, 256, 320, 384, 512, 704, 768, 896, 960, 1024, 1088, 1152, 2688, 4080, MaxDNSPacketSize,
    }

    i := sort.Search(len(boundaries), func(i int) bool {
        return boundaries[i] >= unpaddedLen
    })

    if i < len(boundaries) {
        return boundaries[i]
    }
    return unpaddedLen
}
