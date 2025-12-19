package fuzzer

import (
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// DistributedRole indicates whether this process acts as a server or a client.
type DistributedRole int

const (
	DistributedRoleServer DistributedRole = iota
	DistributedRoleClient
)

// distributedState is attached to Fuzzer and holds all distributed execution state.
type distributedState struct {
	f *Fuzzer

	role DistributedRole

	// server side
	ln        net.Listener
	rpcServer *rpc.Server

	// client side
	rpcClient *rpc.Client
	clientID  string

	// server bookkeeping (optional, for stats/visibility)
	nextID   int64
	mu       sync.Mutex
	inflight map[int64]inflightInfo
}

type inflightInfo struct {
	ClientID string
	SentAt   time.Time
}

// NOTE: net/rpc requires argument and reply types to be exported (or builtin).
// These wire types must be exported, otherwise rpc.Register will fail.

type DistributedFetchArgs struct {
	ClientID string
}

// Server -> client: only the program (no ExecOpts, no coverage, no output).
type DistributedWireRequest struct {
	ProgID    int64
	ProgData  []byte
	Important bool
}

// Client -> server: only an execution acknowledgement.
type DistributedAckArgs struct {
	ClientID string
	ProgID   int64
	OK       bool
	ErrText  string
}

type DistributedAckReply struct{}

// initDistributed initializes distributed mode.
// It tries to listen on addr; if it succeeds, this process becomes the server.
// Otherwise, it tries to connect as a client.
func (f *Fuzzer) initDistributed(addr, clientID string) error {
	ds := &distributedState{
		f:        f,
		inflight: make(map[int64]inflightInfo),
	}

	// Generate a client ID if not provided.
	if clientID == "" {
		host, _ := os.Hostname()
		ds.clientID = fmt.Sprintf("%s-%d", host, os.Getpid())
	} else {
		ds.clientID = clientID
	}

	// Try to become server.
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		ds.role = DistributedRoleServer
		ds.ln = ln
		ds.rpcServer = rpc.NewServer()

		if err := ds.rpcServer.RegisterName("FuzzerDist", (*DistributedRPC)(ds)); err != nil {
			_ = ln.Close()
			return fmt.Errorf("register distributed rpc: %w", err)
		}

		go ds.acceptLoop()
		log.Logf(0, "fuzzer distributed: server listening on %s", addr)
		f.distributed = ds
		return nil
	}

	// Listen failed, try to become client.
	client, err2 := rpc.Dial("tcp", addr)
	if err2 != nil {
		return fmt.Errorf("distributed: listen failed (%v) and dial failed (%v)", err, err2)
	}
	ds.role = DistributedRoleClient
	ds.rpcClient = client
	log.Logf(0, "fuzzer distributed: client connected to %s (id=%s)", addr, ds.clientID)

	f.distributed = ds
	return nil
}

// acceptLoop serves incoming RPC connections on the server.
func (ds *distributedState) acceptLoop() {
	for {
		conn, err := ds.ln.Accept()
		if err != nil {
			// Listener closed or fatal error; just stop accepting.
			return
		}
		go ds.rpcServer.ServeConn(conn)
	}
}

// closeDistributed closes any distributed-related resources.
func (f *Fuzzer) closeDistributed() {
	if f.distributed == nil {
		return
	}
	ds := f.distributed
	if ds.rpcClient != nil {
		_ = ds.rpcClient.Close()
	}
	if ds.ln != nil {
		_ = ds.ln.Close()
	}
}

// distributedNextRequest is used on the client side as a queue.Source callback.
// It fetches a program from the server and returns it as a local queue.Request.
// The request is processed locally (triage/minimize/corpus) by this client's fuzzer.
func (f *Fuzzer) distributedNextRequest() *queue.Request {
	ds := f.distributed
	if ds == nil || ds.role != DistributedRoleClient {
		return nil
	}

	for {
		var wreq DistributedWireRequest
		err := ds.rpcClient.Call(
			"FuzzerDist.Fetch",
			&DistributedFetchArgs{ClientID: ds.clientID},
			&wreq,
		)
		if err != nil {
			log.Logf(0, "distributed Fetch failed: %v (retrying)", err)
			time.Sleep(time.Second)
			continue
		}

		req, err := f.wireToRequest(&wreq)
		if err != nil {
			log.Logf(0, "distributed: bad request from server: %v", err)
			continue
		}

		// Ensure the request participates in the local fuzzer lifecycle.
		// This sets ProgID if needed and installs the local processResult callback.
		f.prepare(req, 0, 0)

		// Best-effort ack to the server (does not affect local processing).
		req.OnDone(func(r *queue.Request, res *queue.Result) bool {
			ds.sendAck(r, res)
			return true
		})

		return req
	}
}

// wireToRequest converts a wire-level request into a local queue.Request on the client.
func (f *Fuzzer) wireToRequest(w *DistributedWireRequest) (*queue.Request, error) {
	var p *prog.Prog
	var err error
	if len(w.ProgData) != 0 {
		// Use NonStrict to be tolerant of minor format changes.
		p, err = f.target.Deserialize(w.ProgData, prog.NonStrict)
		if err != nil {
			return nil, err
		}
	}
	return &queue.Request{
		ProgID:    w.ProgID,
		Prog:      p,
		Important: w.Important,
	}, nil
}

// sendAck sends a lightweight execution acknowledgement from the client to the server.
func (ds *distributedState) sendAck(req *queue.Request, res *queue.Result) {
	if ds.rpcClient == nil {
		return
	}
	ok := true
	errText := ""
	if res != nil && res.Err != nil {
		ok = false
		errText = res.Err.Error()
	}
	args := &DistributedAckArgs{
		ClientID: ds.clientID,
		ProgID:   req.ProgID,
		OK:       ok,
		ErrText:  errText,
	}
	var reply DistributedAckReply
	if err := ds.rpcClient.Call("FuzzerDist.Ack", args, &reply); err != nil {
		log.Logf(0, "distributed Ack failed: %v", err)
	}
}

// DistributedRPC is the RPC receiver type on the server side.
type DistributedRPC distributedState

// Fetch is called by clients to obtain the next program to execute.
// IMPORTANT: This must not consume the server's execution scheduling queue.
// It only generates/serializes a new prog to distribute.
func (ds *DistributedRPC) Fetch(args *DistributedFetchArgs, reply *DistributedWireRequest) error {
	if ds.role != DistributedRoleServer {
		return errors.New("not a distributed server")
	}
	if args == nil || args.ClientID == "" {
		return errors.New("missing ClientID")
	}

	// Generate a new program using the fuzzer generator.
	// We intentionally do NOT call ds.f.Next() here.
	req := ds.f.genFuzz()
	if req == nil || req.Prog == nil {
		return errors.New("failed to generate program")
	}

	// Assign an ID for tracking/ack purposes.
	id := atomic.AddInt64(&ds.nextID, 1)

	*reply = DistributedWireRequest{
		ProgID:    id,
		ProgData:  req.Prog.Serialize(),
		Important: req.Important,
	}

	ds.mu.Lock()
	ds.inflight[id] = inflightInfo{ClientID: args.ClientID, SentAt: time.Now()}
	ds.mu.Unlock()

	return nil
}

// Ack is called by clients to acknowledge they executed a program.
// The server does not use this to drive triage/minimize/corpus; it is purely for confirmation/stats.
func (ds *DistributedRPC) Ack(args *DistributedAckArgs, _ *DistributedAckReply) error {
	if ds.role != DistributedRoleServer {
		return errors.New("not a distributed server")
	}
	if args == nil || args.ClientID == "" {
		return errors.New("missing ClientID")
	}

	ds.mu.Lock()
	_, ok := ds.inflight[args.ProgID]
	delete(ds.inflight, args.ProgID)
	ds.mu.Unlock()

	// Best-effort logging; do not fail the RPC if ProgID is unknown.
	if !ok {
		log.Logf(1, "distributed ack: unknown prog id %d from client %s", args.ProgID, args.ClientID)
		return nil
	}
	if args.OK {
		log.Logf(3, "distributed ack: prog %d executed by client %s", args.ProgID, args.ClientID)
	} else {
		log.Logf(2, "distributed ack: prog %d failed on client %s: %s", args.ProgID, args.ClientID, args.ErrText)
	}
	return nil
}
