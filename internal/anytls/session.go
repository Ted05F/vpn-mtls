package anytls

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// ReadAuth читает аутентификационный префикс клиента и возвращает sha256(password).
// Вызывающая сторона должна заранее выставить дедлайн чтения.
func ReadAuth(r io.Reader) ([32]byte, error) {
	var pre [32 + 2]byte
	var hash [32]byte
	if _, err := io.ReadFull(r, pre[:]); err != nil {
		return hash, err
	}
	copy(hash[:], pre[:32])
	if n := binary.BigEndian.Uint16(pre[32:]); n > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
			return hash, err
		}
	}
	return hash, nil
}

// StreamHandler обрабатывает новый поток: читает адрес назначения и проксирует данные.
// Вызывается в отдельной горутине; обязан закрыть поток.
type StreamHandler func(ctx context.Context, st *Stream)

// SessionConfig — параметры серверной сессии.
type SessionConfig struct {
	Padding      *PaddingScheme
	Handler      StreamHandler
	IdleTimeout  time.Duration // закрыть сессию без входящих кадров дольше этого времени
	WriteTimeout time.Duration
	MaxStreams   int // ограничение одновременно открытых потоков в одной сессии
	Log          *logrus.Entry
}

// Session — серверная сторона одной AnyTLS-сессии поверх одного TLS-соединения.
type Session struct {
	cfg    SessionConfig
	conn   net.Conn
	r      *bufio.Reader
	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex
	mu      sync.Mutex
	streams map[uint32]*Stream

	peerVersion atomic.Int32
	clientName  atomic.Value // string из cmdSettings
	closeOnce   sync.Once

	// Счётчики полезной нагрузки (без служебных кадров и padding).
	BytesUp   atomic.Int64 // клиент → интернет
	BytesDown atomic.Int64 // интернет → клиент
}

// NewSession создаёт сессию. r — буферизованный читатель того же conn,
// из которого уже прочитан аутентификационный префикс.
func NewSession(ctx context.Context, conn net.Conn, r *bufio.Reader, cfg SessionConfig) *Session {
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = 1024
	}
	if cfg.Log == nil {
		cfg.Log = logrus.NewEntry(logrus.StandardLogger())
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Session{cfg: cfg, conn: conn, r: r, ctx: ctx, cancel: cancel, streams: make(map[uint32]*Stream)}
	s.clientName.Store("")
	return s
}

// Context отменяется при закрытии сессии.
func (s *Session) Context() context.Context { return s.ctx }

// ClientName — значение client=... из cmdSettings (например "sing-box/1.14.2").
func (s *Session) ClientName() string { return s.clientName.Load().(string) }

// Serve выполняет цикл приёма кадров до ошибки или закрытия сессии.
func (s *Session) Serve() error {
	defer s.Close()
	go func() {
		<-s.ctx.Done()
		s.Close()
	}()

	var (
		h        header
		buf      = make([]byte, maxFrameData)
		settings bool
	)
	for {
		if s.cfg.IdleTimeout > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}
		if _, err := io.ReadFull(s.r, h[:]); err != nil {
			return err
		}
		data := buf[:h.length()]
		if _, err := io.ReadFull(s.r, data); err != nil {
			return err
		}
		sid := h.streamID()

		switch h.cmd() {
		case cmdPSH:
			if st := s.stream(sid); st != nil && len(data) > 0 {
				s.BytesUp.Add(int64(len(data)))
				st.deliver(data)
			}

		case cmdSYN:
			if !settings {
				s.alert("client did not send its settings")
				return errors.New("SYN before settings")
			}
			s.openStream(sid)

		case cmdFIN:
			s.mu.Lock()
			st := s.streams[sid]
			delete(s.streams, sid)
			s.mu.Unlock()
			if st != nil {
				st.terminate(io.EOF)
			}

		case cmdSettings:
			settings = true
			m := parseStringMap(data)
			s.clientName.Store(m["client"])
			if m["padding-md5"] != s.cfg.Padding.MD5 {
				if err := s.writeFrame(cmdUpdatePaddingScheme, 0, s.cfg.Padding.Raw); err != nil {
					return err
				}
			}
			if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
				s.peerVersion.Store(int32(v))
				if err := s.writeFrame(cmdServerSettings, 0, encodeStringMap("v", strconv.Itoa(ProtocolVersion))); err != nil {
					return err
				}
			}

		case cmdHeartRequest:
			if err := s.writeFrame(cmdHeartResponse, sid, nil); err != nil {
				return err
			}

		default:
			// cmdWaste, cmdHeartResponse и команды, которые клиент слать не должен, — игнорируем.
		}
	}
}

func (s *Session) openStream(sid uint32) {
	s.mu.Lock()
	if _, exists := s.streams[sid]; exists {
		s.mu.Unlock()
		return
	}
	st := newStream(sid, s)
	if len(s.streams) >= s.cfg.MaxStreams {
		s.mu.Unlock()
		s.cfg.Log.Warn("anytls: stream limit reached")
		st.HandshakeFailure(errors.New("too many streams"))
		_ = s.writeFrame(cmdFIN, sid, nil)
		return
	}
	s.streams[sid] = st
	s.mu.Unlock()
	go s.cfg.Handler(s.ctx, st)
}

func (s *Session) stream(sid uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[sid]
}

// Close закрывает сессию и все её потоки.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		s.mu.Lock()
		streams := s.streams
		s.streams = map[uint32]*Stream{}
		s.mu.Unlock()
		for _, st := range streams {
			st.terminate(io.ErrClosedPipe)
		}
		err = s.conn.Close()
	})
	return err
}

func (s *Session) closed() bool { return s.ctx.Err() != nil }

func (s *Session) alert(msg string) {
	_ = s.writeFrame(cmdAlert, 0, []byte(msg))
}

func (s *Session) writeFrame(cmd byte, sid uint32, data []byte) error {
	return s.writeRaw(appendFrame(make([]byte, 0, headerSize+len(data)), cmd, sid, data))
}

func (s *Session) writeRaw(b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	_, err := s.conn.Write(b)
	if err != nil {
		go s.Close()
	}
	return err
}

// ── Stream ──────────────────────────────────────────────────────────────────

// Stream — один логический поток (одно проксируемое соединение) внутри сессии.
// Реализует io.ReadWriteCloser.
type Stream struct {
	id   uint32
	sess *Session
	pr   *io.PipeReader
	pw   *io.PipeWriter

	closeOnce  sync.Once
	reportOnce sync.Once
	dead       atomic.Bool
}

func newStream(id uint32, s *Session) *Stream {
	pr, pw := io.Pipe()
	return &Stream{id: id, sess: s, pr: pr, pw: pw}
}

// Session возвращает сессию, которой принадлежит поток.
func (st *Stream) Session() *Session { return st.sess }

func (st *Stream) Read(p []byte) (int, error) { return st.pr.Read(p) }

// Write отправляет данные клиенту, разбивая их на кадры cmdPSH.
func (st *Stream) Write(p []byte) (int, error) {
	if st.dead.Load() || st.sess.closed() {
		return 0, io.ErrClosedPipe
	}
	out := make([]byte, 0, len(p)+headerSize*(len(p)/maxFrameData+1))
	for rest := p; len(rest) > 0; {
		n := min(len(rest), maxFrameData)
		out = appendFrame(out, cmdPSH, st.id, rest[:n])
		rest = rest[n:]
	}
	if err := st.sess.writeRaw(out); err != nil {
		return 0, err
	}
	st.sess.BytesDown.Add(int64(len(p)))
	return len(p), nil
}

// Close закрывает поток по инициативе сервера и уведомляет клиента (cmdFIN).
func (st *Stream) Close() error {
	st.closeOnce.Do(func() {
		st.dead.Store(true)
		st.pr.Close()
		st.pw.Close()
		st.sess.mu.Lock()
		delete(st.sess.streams, st.id)
		st.sess.mu.Unlock()
		if !st.sess.closed() {
			_ = st.sess.writeFrame(cmdFIN, st.id, nil)
		}
	})
	return nil
}

// terminate закрывает поток без отправки cmdFIN (клиент закрыл поток или сессия завершилась).
func (st *Stream) terminate(err error) {
	st.closeOnce.Do(func() {
		st.dead.Store(true)
		st.pw.CloseWithError(err)
	})
}

// deliver передаёт данные читателю потока. Блокируется, пока читатель их не заберёт —
// это естественное управление потоком (backpressure), как в эталонной реализации.
func (st *Stream) deliver(b []byte) {
	if st.dead.Load() {
		return
	}
	_, _ = st.pw.Write(b)
}

// HandshakeSuccess сообщает клиенту (протокол v2), что исходящее соединение установлено.
func (st *Stream) HandshakeSuccess() {
	st.reportOnce.Do(func() {
		if st.sess.peerVersion.Load() >= 2 {
			_ = st.sess.writeFrame(cmdSYNACK, st.id, nil)
		}
	})
}

// HandshakeFailure сообщает клиенту (протокол v2) об ошибке открытия соединения.
func (st *Stream) HandshakeFailure(err error) {
	st.reportOnce.Do(func() {
		if st.sess.peerVersion.Load() >= 2 {
			msg := []byte(err.Error())
			if len(msg) > 512 {
				msg = msg[:512]
			}
			_ = st.sess.writeFrame(cmdSYNACK, st.id, msg)
		}
	})
}
