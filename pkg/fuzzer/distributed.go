package fuzzer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

// DistributedRole indicates whether this process acts as a server or a client.
type DistributedRole int

const (
	DistributedRoleServer DistributedRole = iota
	DistributedRoleClient
)

// progExecState describes per-client execution state for a single prog.
type progExecState int

const (
	progStateNotSent progExecState = iota // known globally, but not yet assigned to this client
	progStatePending                      // sent to this client, waiting for execution
	progStateOK                           // client reported success
	progStateFailed                       // client reported failure
)

// storedProg is a globally generated program on the server.
type storedProg struct {
	ID        int64
	ProgData  []byte
	Important bool
}

// clientState tracks what each client has already seen and how it went.
type clientState struct {
	ID      string
	NextIdx int                     // index into distributedState.programs slice
	Status  map[int64]progExecState // progID -> state
}

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

	// server global program registry and per-client progress.
	mu       sync.Mutex
	cond     *sync.Cond
	programs []storedProg
	nextID   int64

	clients map[string]*clientState

	dumpWorkdir string
	dumpPeriod  time.Duration
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
		f:       f,
		clients: make(map[string]*clientState),
	}
	ds.dumpWorkdir = f.Config.Workdir
	ds.dumpPeriod = f.Config.DistributedDumpPeriod
	ds.cond = sync.NewCond(&ds.mu)

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
		ds.startClientStateDumpLoop()
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

// getOrCreateClientLocked returns the clientState for a given client ID.
// ds.mu must be held by the caller.
func (ds *distributedState) getOrCreateClientLocked(id string) *clientState {
	if st, ok := ds.clients[id]; ok {
		return st
	}
	st := &clientState{
		ID:     id,
		Status: make(map[int64]progExecState),
	}
	ds.clients[id] = st
	return st
}

// registerProgFromServer is called on the server each time we generate
// a new fuzz program (in genFuzz). It assigns a global ProgID and stores
// the serialized program so that all current and future clients can execute it.
func (ds *distributedState) registerProgFromServer(req *queue.Request) {
	if req == nil || req.Prog == nil {
		return
	}
	data := req.Prog.Serialize()

	// Allocate a new global ID and append to the global program list.
	id := atomic.AddInt64(&ds.nextID, 1)

	ds.mu.Lock()
	ds.programs = append(ds.programs, storedProg{
		ID:        id,
		ProgData:  data,
		Important: req.Important,
	})
	// Wake up any clients blocked in Fetch waiting for new programs.
	ds.cond.Broadcast()
	ds.mu.Unlock()

	// Make the request use this global ID (prepare() will not override it).
	req.ProgID = id
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
		// This installs the local processResult callback.
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
// It does not consume the server's own scheduling queues; instead it
// walks the global program list and assigns any program that the given
// client has not yet executed.
//
// For a newly joined client, NextIdx starts at 0, so it will re-run all
// previously generated programs in order.
func (ds *DistributedRPC) Fetch(args *DistributedFetchArgs, reply *DistributedWireRequest) error {
	if ds.role != DistributedRoleServer {
		return errors.New("not a distributed server")
	}
	if args == nil || args.ClientID == "" {
		return errors.New("missing ClientID")
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	st := (*distributedState)(ds).getOrCreateClientLocked(args.ClientID)

	for {
		if st.NextIdx < len(ds.programs) {
			sp := ds.programs[st.NextIdx]
			st.NextIdx++
			st.Status[sp.ID] = progStatePending

			*reply = DistributedWireRequest{
				ProgID:    sp.ID,
				ProgData:  sp.ProgData,
				Important: sp.Important,
			}
			return nil
		}
		// No new programs yet: wait until registerProgFromServer() broadcasts.
		ds.cond.Wait()
	}
}

// Ack is called by clients to acknowledge they executed a program.
// The server updates per-client state; this is only for bookkeeping/stats.
func (ds *DistributedRPC) Ack(args *DistributedAckArgs, _ *DistributedAckReply) error {
	if ds.role != DistributedRoleServer {
		return errors.New("not a distributed server")
	}
	if args == nil || args.ClientID == "" {
		return errors.New("missing ClientID")
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	st := (*distributedState)(ds).getOrCreateClientLocked(args.ClientID)

	if args.OK {
		st.Status[args.ProgID] = progStateOK
		log.Logf(3, "distributed ack: prog %d executed OK by client %s", args.ProgID, args.ClientID)
	} else {
		st.Status[args.ProgID] = progStateFailed
		log.Logf(2, "distributed ack: prog %d failed on client %s: %s",
			args.ProgID, args.ClientID, args.ErrText)
	}
	return nil
}

const (
	distributedDumpFilename      = "distributed_clients.tsv"
	defaultDistributedDumpPeriod = 20 * time.Second
)

type clientStateSnapshot struct {
	id      string
	nextIdx int
	status  map[int64]progExecState
}

func (ds *distributedState) startClientStateDumpLoop() {
	if ds == nil || ds.role != DistributedRoleServer {
		return
	}
	if ds.dumpWorkdir == "" {
		return
	}
	period := ds.dumpPeriod
	if period == 0 {
		period = defaultDistributedDumpPeriod
	}
	go func() {
		ticker := time.NewTicker(period)
		defer ticker.Stop()

		// Dump once on startup.
		ds.dumpClientStatesToFile()

		for range ticker.C {
			ds.dumpClientStatesToFile()
		}
	}()
}

func (ds *distributedState) dumpClientStatesToFile() {
	workdir := ds.dumpWorkdir
	if workdir == "" {
		return
	}
	outPath := filepath.Join(workdir, distributedDumpFilename)
	tmpPath := outPath + ".tmp"

	// Snapshot under lock to avoid racing with Fetch/Ack.
	var snaps []clientStateSnapshot
	var totalPrograms int
	ds.mu.Lock()
	totalPrograms = len(ds.programs)
	snaps = make([]clientStateSnapshot, 0, len(ds.clients))
	for id, st := range ds.clients {
		m := make(map[int64]progExecState, len(st.Status))
		for pid, s := range st.Status {
			m[pid] = s
		}
		snaps = append(snaps, clientStateSnapshot{
			id:      id,
			nextIdx: st.NextIdx,
			status:  m,
		})
	}
	ds.mu.Unlock()

	sort.Slice(snaps, func(i, j int) bool { return snaps[i].id < snaps[j].id })

	// Build TSV.
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "# generated_at\t%s\n", time.Now().Format(time.RFC3339Nano))
	fmt.Fprintf(buf, "# total_programs\t%d\n", totalPrograms)
	fmt.Fprintf(buf, "# columns are tab-separated (TSV)\n")

	fmt.Fprintf(buf, "\n[clients]\n")
	fmt.Fprintf(buf, "client_id\tnext_idx\ttotal_programs\tnot_assigned\tpending\tok\tfailed\n")
	for _, c := range snaps {
		var pending, ok, failed int
		for _, st := range c.status {
			switch st {
			case progStatePending:
				pending++
			case progStateOK:
				ok++
			case progStateFailed:
				failed++
			}
		}
		notAssigned := totalPrograms - c.nextIdx
		if notAssigned < 0 {
			notAssigned = 0
		}
		fmt.Fprintf(buf, "%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
			c.id, c.nextIdx, totalPrograms, notAssigned, pending, ok, failed)
	}

	// Dump the full per-prog state map as a separate table.
	// This is the actual content of clients[*].Status.
	fmt.Fprintf(buf, "\n[states]\n")
	fmt.Fprintf(buf, "client_id\tprog_id\tstate\n")
	for _, c := range snaps {
		ids := make([]int64, 0, len(c.status))
		for pid := range c.status {
			ids = append(ids, pid)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, pid := range ids {
			fmt.Fprintf(buf, "%s\t%d\t%s\n", c.id, pid, progExecStateString(c.status[pid]))
		}
	}

	// Write to tmp then rename to overwrite old file.
	if err := os.WriteFile(tmpPath, buf.Bytes(), osutil.DefaultFilePerm); err != nil {
		log.Logf(0, "distributed dump: write %s failed: %v", tmpPath, err)
		return
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		// Best-effort: remove existing and retry.
		_ = os.Remove(outPath)
		if err2 := os.Rename(tmpPath, outPath); err2 != nil {
			log.Logf(0, "distributed dump: rename %s -> %s failed: %v", tmpPath, outPath, err2)
			_ = os.Remove(tmpPath)
			return
		}
	}
}

func progExecStateString(st progExecState) string {
	switch st {
	case progStateNotSent:
		return "NOT_SENT"
	case progStatePending:
		return "PENDING"
	case progStateOK:
		return "OK"
	case progStateFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}
