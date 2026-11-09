package sink

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// record is one request payload waiting to be sent.
type record struct {
	seq     uint64 // identifies the record, unique in the process
	kind    byte
	samples int
	data    []byte
}

// nextSeq numbers records. Starting from the clock keeps numbers of a new
// run above those of records left on disk by a previous one.
var nextSeq atomic.Uint64

func init() { nextSeq.Store(uint64(time.Now().UnixNano())) }

// fifo is the queue of a sink's requests: in memory, and in the disk
// buffer while the destination is down or memory is full. Every record on
// disk is older than every record in memory, so the head is the disk's
// first record, if any, then memory's. Only the sender reads it.
type fifo struct {
	mu       sync.Mutex
	wake     chan struct{}
	mem      []record
	memBytes int
	disk     *diskQueue // nil: no disk buffer and nothing left on disk
	limit    int64      // disk_buffer; 0: nothing new is written to disk
	down     bool
	closed   bool
	log      *slog.Logger
}

func newFIFO(disk *diskQueue, limit int64, log *slog.Logger) *fifo {
	f := &fifo{wake: make(chan struct{}, 1), disk: disk, limit: limit, log: log}
	if disk != nil && limit > 0 {
		disk.setLimit(limit)
	}
	return f
}

// own makes f the reader of its disk queue.
func (f *fifo) own() {
	if f.disk != nil {
		f.disk.setOwner(f)
	}
}

// hasDisk reports whether f writes to a disk buffer.
func (f *fifo) hasDisk() bool { return f.disk != nil && f.limit > 0 }

// push queues r and returns the number of samples dropped to make room.
func (f *fifo) push(r record) int {
	r.seq = nextSeq.Add(1)
	f.mu.Lock()
	f.mem = append(f.mem, r)
	f.memBytes += len(r.data)
	dropped := 0
	if f.down || f.memBytes > memoryLimit {
		dropped = f.spill()
	}
	f.mu.Unlock()
	f.signal()
	return dropped
}

func (f *fifo) signal() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// spill moves memory to the disk buffer or, without one, drops the oldest
// records beyond the memory limit. Called with f.mu held.
func (f *fifo) spill() (dropped int) {
	if f.hasDisk() {
		for _, r := range f.mem {
			dropped += f.disk.append(r, f.limit)
		}
		f.mem, f.memBytes = nil, 0
		return dropped
	}
	for f.memBytes > memoryLimit && len(f.mem) > 0 {
		dropped += f.mem[0].samples
		f.memBytes -= len(f.mem[0].data)
		f.mem[0] = record{}
		f.mem = f.mem[1:]
	}
	return dropped
}

// setDown records whether the destination is reachable. While it is not,
// everything goes to the disk buffer.
func (f *fifo) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
	if down {
		if n := f.spill(); n > 0 {
			f.log.Warn("sink: disk buffer full, oldest samples dropped", "samples", n)
		}
	}
}

func (f *fifo) isDown() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.down
}

// head returns the oldest record, waiting for one until ctx is done.
func (f *fifo) head(ctx context.Context) (record, bool) {
	for {
		f.mu.Lock()
		if f.disk != nil && f.disk.isOwner(f) {
			if r, ok := f.disk.peek(); ok {
				f.mu.Unlock()
				return r, true
			}
		}
		if len(f.mem) > 0 {
			r := f.mem[0]
			f.mu.Unlock()
			return r, true
		}
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return record{}, false
		case <-f.wake:
		}
	}
}

// pop removes the head if it is still the record seq: it may have been
// dropped meanwhile to make room.
func (f *fifo) pop(seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.disk != nil && f.disk.isOwner(f) && f.disk.pop(seq) {
		return
	}
	if len(f.mem) > 0 && f.mem[0].seq == seq {
		f.memBytes -= len(f.mem[0].data)
		f.mem[0] = record{}
		f.mem = f.mem[1:]
	}
}

// backlog returns the number of samples waiting.
func (f *fifo) backlog() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, r := range f.mem {
		n += int64(r.samples)
	}
	if f.disk != nil {
		n += f.disk.backlog()
	}
	return n
}

func (f *fifo) diskBytes() int64 {
	if f.disk == nil {
		return 0
	}
	return f.disk.bytes()
}

func (f *fifo) memoryLen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mem)
}

// close moves what is left in memory to the disk buffer and releases it.
// It returns the number of samples lost (no disk buffer).
func (f *fifo) close() (lost int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0
	}
	f.closed = true
	if f.hasDisk() {
		if n := f.spill(); n > 0 {
			f.log.Warn("sink: disk buffer full, oldest samples dropped", "samples", n)
		}
	} else {
		for _, r := range f.mem {
			lost += r.samples
		}
	}
	f.mem, f.memBytes = nil, 0
	if f.disk != nil {
		f.disk.release(f)
	}
	return lost
}

// The disk buffer of a sink is a directory of segment files,
// <seq>.seg, read in order. Each record is a header and a payload:
//
//	length  uint32  payload length
//	crc     uint32  CRC-32C of the rest of the header and the payload
//	seq     uint64
//	samples uint32
//	kind    uint8
//
// The read position is kept in the file "cursor" ("<segment> <offset>"):
// a record sent again after a crash is a duplicate both databases ignore.
// Segments are deleted once read, or, the oldest first, when the buffer
// exceeds its limit.
const headerSize = 21

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type diskQueue struct {
	mu      sync.Mutex
	dir     string
	log     *slog.Logger
	segs    []*segment
	head    int      // next record of segs[0]
	r       *os.File // reads segs[0]
	w       *os.File // appends to the last segment
	size    int64
	samples int64
	segMax  int64
	peeked  *record
	refs    int
	owner   *fifo
}

type segment struct {
	id   uint64
	size int64
	recs []recMeta
}

type recMeta struct {
	off     int64
	length  int32
	samples int32
	seq     uint64
	kind    byte
}

// The open disk queues, by directory: a sink replaced by a reload shares
// its queue with the new one.
var registry = struct {
	sync.Mutex
	m map[string]*diskQueue
}{m: map[string]*diskQueue{}}

// acquire opens the disk queue of dir, or shares it when a sink already
// has it open (shared is then true). Without create, it returns nil when
// dir holds no segment.
func acquire(dir string, create bool, log *slog.Logger) (q *diskQueue, shared bool, err error) {
	registry.Lock()
	defer registry.Unlock()
	if q := registry.m[dir]; q != nil {
		q.mu.Lock()
		q.refs++
		q.mu.Unlock()
		return q, true, nil
	}
	if !create {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if !hasSegments(entries) {
			return nil, false, nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, err
	}
	q = &diskQueue{dir: dir, log: log, refs: 1, segMax: 64 << 20}
	if err := q.load(); err != nil {
		q.closeFiles()
		return nil, false, err
	}
	registry.m[dir] = q
	return q, false, nil
}

func hasSegments(entries []fs.DirEntry) bool {
	for _, e := range entries {
		if _, ok := segmentID(e.Name()); ok {
			return true
		}
	}
	return false
}

func segmentID(name string) (uint64, bool) {
	s, ok := strings.CutSuffix(name, ".seg")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseUint(s, 10, 64)
	return id, err == nil
}

func (q *diskQueue) segPath(id uint64) string {
	return filepath.Join(q.dir, fmt.Sprintf("%020d.seg", id))
}

// load reads the segment headers and the cursor. A record cut short by a
// crash ends its segment: the file is truncated there.
func (q *diskQueue) load() error {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	var ids []uint64
	for _, e := range entries {
		if id, ok := segmentID(e.Name()); ok {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	curSeg, curOff := q.readCursor()
	for _, id := range ids {
		if id < curSeg {
			os.Remove(q.segPath(id)) // read before the crash
			continue
		}
		s, err := q.scan(id)
		if err != nil {
			return err
		}
		q.segs = append(q.segs, s)
		q.size += s.size
	}
	if len(q.segs) > 0 && q.segs[0].id == curSeg {
		for q.head < len(q.segs[0].recs) && q.segs[0].recs[q.head].off < curOff {
			q.head++
		}
	}
	for i, s := range q.segs {
		from := 0
		if i == 0 {
			from = q.head
		}
		for _, m := range s.recs[from:] {
			q.samples += int64(m.samples)
		}
	}
	q.trimHead()
	return nil
}

// scan reads the record headers of one segment.
func (q *diskQueue) scan(id uint64) (*segment, error) {
	path := q.segPath(id)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	s := &segment{id: id}
	var h [headerSize]byte
	var off int64
	for off < st.Size() {
		if _, err := f.ReadAt(h[:], off); err != nil {
			break
		}
		n := int64(binary.LittleEndian.Uint32(h[0:]))
		if off+headerSize+n > st.Size() {
			break
		}
		s.recs = append(s.recs, recMeta{
			off: off, length: int32(n), seq: binary.LittleEndian.Uint64(h[8:]),
			samples: int32(binary.LittleEndian.Uint32(h[16:])), kind: h[20],
		})
		off += headerSize + n
	}
	if off < st.Size() {
		q.log.Warn("sink: disk buffer: incomplete record at the end of a segment removed", "file", path,
			"bytes", st.Size()-off)
		if err := os.Truncate(path, off); err != nil {
			return nil, err
		}
	}
	s.size = off
	return s, nil
}

func (q *diskQueue) readCursor() (seg uint64, off int64) {
	b, err := os.ReadFile(filepath.Join(q.dir, "cursor"))
	if err != nil {
		return 0, 0
	}
	if _, err := fmt.Sscan(string(b), &seg, &off); err != nil {
		return 0, 0
	}
	return seg, off
}

// writeCursor records the read position. Called with q.mu held.
func (q *diskQueue) writeCursor() {
	path := filepath.Join(q.dir, "cursor")
	if len(q.segs) == 0 {
		os.Remove(path)
		return
	}
	s := q.segs[0]
	off := s.size
	if q.head < len(s.recs) {
		off = s.recs[q.head].off
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, fmt.Appendf(nil, "%d %d\n", s.id, off), 0o644); err == nil {
		os.Rename(tmp, path)
	}
}

func (q *diskQueue) setLimit(limit int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	// Several segments, so that dropping the oldest frees a fraction only.
	q.segMax = min(max(limit/8, 64<<10), 64<<20)
}

func (q *diskQueue) setOwner(f *fifo) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.owner = f
}

func (q *diskQueue) isOwner(f *fifo) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.owner == f
}

func (q *diskQueue) backlog() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.samples
}

func (q *diskQueue) bytes() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.size
}

// append writes r and, beyond limit, drops the oldest segments. It returns
// the number of samples dropped.
func (q *diskQueue) append(r record, limit int64) (dropped int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	size := int64(headerSize + len(r.data))
	if size > limit {
		return r.samples
	}
	if len(q.segs) == 0 || q.w == nil || q.segs[len(q.segs)-1].size >= q.segMax {
		if err := q.rotate(); err != nil {
			q.log.Error("sink: disk buffer: cannot create a segment", "dir", q.dir, "err", err)
			return r.samples
		}
	}
	s := q.segs[len(q.segs)-1]
	buf := make([]byte, headerSize, size)
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(r.data)))
	binary.LittleEndian.PutUint64(buf[8:], r.seq)
	binary.LittleEndian.PutUint32(buf[16:], uint32(r.samples))
	buf[20] = r.kind
	buf = append(buf, r.data...)
	binary.LittleEndian.PutUint32(buf[4:], crc32.Checksum(buf[8:], castagnoli))
	if _, err := q.w.Write(buf); err != nil {
		q.log.Error("sink: disk buffer: write failed", "dir", q.dir, "err", err)
		// Never append after a partial write: start a new segment.
		q.w.Close()
		q.w = nil
		os.Truncate(q.segPath(s.id), s.size)
		return r.samples
	}
	s.recs = append(s.recs, recMeta{off: s.size, length: int32(len(r.data)), seq: r.seq,
		samples: int32(r.samples), kind: r.kind})
	s.size += size
	q.size += size
	q.samples += int64(r.samples)
	for q.size > limit && len(q.segs) > 0 {
		dropped += q.dropHead()
	}
	return dropped
}

// rotate starts a new segment. Called with q.mu held.
func (q *diskQueue) rotate() error {
	var id uint64 = 1
	if n := len(q.segs); n > 0 {
		id = q.segs[n-1].id + 1
	}
	if q.w != nil {
		q.w.Sync()
		q.w.Close()
		q.w = nil
	}
	w, err := os.OpenFile(q.segPath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	q.w = w
	q.segs = append(q.segs, &segment{id: id})
	return nil
}

// dropHead deletes the oldest segment and returns its unread samples.
// Called with q.mu held.
func (q *diskQueue) dropHead() int {
	s := q.segs[0]
	n := 0
	for _, m := range s.recs[q.head:] {
		n += int(m.samples)
	}
	q.removeHead()
	q.samples -= int64(n)
	q.writeCursor()
	return n
}

// removeHead deletes the first segment. Called with q.mu held.
func (q *diskQueue) removeHead() {
	s := q.segs[0]
	if q.r != nil {
		q.r.Close()
		q.r = nil
	}
	if len(q.segs) == 1 && q.w != nil {
		q.w.Close()
		q.w = nil
	}
	os.Remove(q.segPath(s.id))
	q.size -= s.size
	q.segs = q.segs[1:]
	q.head = 0
	q.peeked = nil
}

// trimHead deletes fully read segments. Called with q.mu held.
func (q *diskQueue) trimHead() {
	for len(q.segs) > 0 && q.head >= len(q.segs[0].recs) {
		q.removeHead() // the last one too: the next append starts a segment
	}
	q.writeCursor()
}

// peek returns the first unread record. Corrupt records are skipped.
func (q *diskQueue) peek() (record, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if q.peeked != nil {
			return *q.peeked, true
		}
		if len(q.segs) == 0 || q.head >= len(q.segs[0].recs) {
			return record{}, false
		}
		s := q.segs[0]
		m := s.recs[q.head]
		r, err := q.read(s, m)
		if err != nil {
			q.log.Warn("sink: disk buffer: unreadable record skipped", "file", q.segPath(s.id),
				"offset", m.off, "samples", m.samples, "err", err)
			q.advance()
			continue
		}
		q.peeked = &r
		return r, true
	}
}

func (q *diskQueue) read(s *segment, m recMeta) (record, error) {
	if q.r == nil {
		f, err := os.Open(q.segPath(s.id))
		if err != nil {
			return record{}, err
		}
		q.r = f
	}
	buf := make([]byte, headerSize+int(m.length))
	if n, err := q.r.ReadAt(buf, m.off); n < len(buf) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return record{}, err
	}
	if crc32.Checksum(buf[8:], castagnoli) != binary.LittleEndian.Uint32(buf[4:]) {
		return record{}, errors.New("checksum mismatch")
	}
	return record{seq: m.seq, kind: m.kind, samples: int(m.samples), data: buf[headerSize:]}, nil
}

// pop removes the first record if it is seq.
func (q *diskQueue) pop(seq uint64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.segs) == 0 || q.head >= len(q.segs[0].recs) || q.segs[0].recs[q.head].seq != seq {
		return false
	}
	q.advance()
	return true
}

// advance moves past the first record. Called with q.mu held.
func (q *diskQueue) advance() {
	q.samples -= int64(q.segs[0].recs[q.head].samples)
	q.head++
	q.peeked = nil
	q.trimHead()
}

// release drops a reference; the last one closes the files.
func (q *diskQueue) release(f *fifo) {
	registry.Lock()
	defer registry.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.owner == f {
		q.owner = nil
	}
	if q.refs--; q.refs == 0 {
		q.closeFiles()
		delete(registry.m, q.dir)
	}
}

func (q *diskQueue) closeFiles() {
	if q.r != nil {
		q.r.Close()
		q.r = nil
	}
	if q.w != nil {
		q.w.Sync()
		q.w.Close()
		q.w = nil
	}
}
