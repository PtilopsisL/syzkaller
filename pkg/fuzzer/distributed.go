package fuzzer

import (
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
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

	// server inflight requests: ProgID -> original *queue.Request
	mu       sync.Mutex
	inflight map[int64]*queue.Request
}

// NOTE: net/rpc requires argument and reply types to be exported (or builtin).
// These wire types must be exported, otherwise rpc.Register will fail.

type DistributedFetchArgs struct {
	ClientID string
}

type DistributedWireRequest struct {
	ProgID    int64
	ExecOpts  flatrpc.ExecOpts
	ProgData  []byte
	Important bool
}

type DistributedWireResult struct {
	ProgID int64

	Info    *flatrpc.ProgInfo
	Output  []byte
	Status  queue.Status
	ErrText string
}

// initDistributed initializes distributed mode.
// It tries to listen on addr; if it succeeds, this process becomes the server.
// Otherwise, it tries to connect as a client.
func (f *Fuzzer) initDistributed(addr, clientID string) error {
	ds := &distributedState{
		f:        f,
		inflight: make(map[int64]*queue.Request),
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

		// Register an EXPORTED receiver type (DistributedRPC) and EXPORTED args/reply types.
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
// It fetches the next request from the server via RPC and converts it to a local queue.Request.
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

		// On the client, when execution finishes, send the result back to the server.
		req.OnDone(func(r *queue.Request, res *queue.Result) bool {
			ds.sendResult(r, res)
			// The client does not run processResult; it only reports back.
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
		ExecOpts:  w.ExecOpts,
		Important: w.Important,
	}, nil
}

// sendResult sends the execution result from the client back to the server.
func (ds *distributedState) sendResult(req *queue.Request, res *queue.Result) {
	if ds.rpcClient == nil {
		return
	}
	wr := &DistributedWireResult{
		ProgID: req.ProgID,
		Info:   res.Info,
		Output: res.Output,
		Status: res.Status,
	}
	if res.Err != nil {
		wr.ErrText = res.Err.Error()
	}
	var nothing struct{}
	if err := ds.rpcClient.Call("FuzzerDist.Report", wr, &nothing); err != nil {
		log.Logf(0, "distributed Report failed: %v", err)
	}
}

// DistributedRPC is the RPC receiver type on the server side.
// It is a thin wrapper around distributedState; net/rpc prefers exported receiver types.
type DistributedRPC distributedState

// Fetch is called by clients to obtain the next request to execute.
func (ds *DistributedRPC) Fetch(args *DistributedFetchArgs, reply *DistributedWireRequest) error {
	if ds.role != DistributedRoleServer {
		return errors.New("not a distributed server")
	}

	// Use the existing Fuzzer.Next() scheduling logic on the server.
	req := ds.f.Next()
	if req == nil {
		return errors.New("nil request from fuzzer")
	}

	var progData []byte
	if req.Prog != nil {
		progData = req.Prog.Serialize()
	}

	*reply = DistributedWireRequest{
		ProgID:    req.ProgID,
		ExecOpts:  req.ExecOpts,
		ProgData:  progData,
		Important: req.Important,
	}

	// Track this request as in-flight until the client reports back.
	ds.mu.Lock()
	ds.inflight[req.ProgID] = req
	ds.mu.Unlock()
	return nil
}

// Report is called by clients to report back the execution result.
// The server finds the original queue.Request and calls Done(), which
// triggers the usual processResult / triage logic.
func (ds *DistributedRPC) Report(args *DistributedWireResult, _ *struct{}) error {
	if ds.role != DistributedRoleServer {
		return errors.New("not a distributed server")
	}

	ds.mu.Lock()
	req := ds.inflight[args.ProgID]
	delete(ds.inflight, args.ProgID)
	ds.mu.Unlock()

	if req == nil {
		// Possibly already cleaned up or unknown ProgID; ignore.
		return nil
	}

	var err error
	if args.ErrText != "" {
		err = errors.New(args.ErrText)
	}

	req.Done(&queue.Result{
		Info:   args.Info,
		Output: args.Output,
		Status: args.Status,
		Err:    err,
	})
	return nil
}
