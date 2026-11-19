package sshx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

var (
	ErrHostKeyUnknown  = errors.New("host key unknown; confirmation required")
	ErrHostKeyMismatch = errors.New("host key fingerprint changed")
	ErrOutputTooLarge  = errors.New("command output too large")
)

type Config struct {
	DialTimeout time.Duration
	CmdTimeout  time.Duration
	MaxOutput   int64
	MaxPerHost  int
}

type HostKeyCallback func(hostname string, remote net.Addr, key ssh.PublicKey) error

type JumpSpec struct {
	Host       string
	Port       int
	User       string
	Password   string
	PrivateKey []byte
	Passphrase string
	KnownFP    string
	SocksProxy string // host:port, no credentials
}

type ConnectOpts struct {
	Host       string
	Port       int
	User       string
	Password   string
	PrivateKey []byte
	Passphrase string
	KnownFP    string // empty = first connect
	PendingOK  bool   // accept pending fingerprint this call
	OnPending  func(fp string)
	Jump       *JumpSpec
	SocksProxy string // host:port, no credentials
}

type Client struct {
	cfg   Config
	semas sync.Map // host -> *semaphore
}

type semaphore struct {
	ch chan struct{}
}

func New(cfg Config) *Client {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.CmdTimeout == 0 {
		cfg.CmdTimeout = 5 * time.Minute
	}
	if cfg.MaxOutput == 0 {
		cfg.MaxOutput = 2 << 20
	}
	if cfg.MaxPerHost == 0 {
		cfg.MaxPerHost = 2
	}
	return &Client{cfg: cfg}
}

func (c *Client) acquire(host string) func() {
	v, _ := c.semas.LoadOrStore(host, &semaphore{ch: make(chan struct{}, c.cfg.MaxPerHost)})
	sem := v.(*semaphore)
	sem.ch <- struct{}{}
	return func() { <-sem.ch }
}

// RemoteExit reports a remote command failure that left the connection up.
func RemoteExit(err error) bool {
	var exit *ssh.ExitError
	return errors.As(err, &exit)
}

// ErrStillUp means a TCP wait for the port to close timed out while it stayed open.
var ErrStillUp = errors.New("tcp stayed up")

// WaitTCP polls host:port until it matches wantUp or the timeout elapses.
func WaitTCP(ctx context.Context, host string, port int, wantUp bool, timeout time.Duration) error {
	if port <= 0 {
		port = 22
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if conn != nil {
			_ = conn.Close()
		}
		if (err == nil) == wantUp {
			return nil
		}
		if time.Now().After(deadline) {
			if !wantUp {
				return ErrStillUp
			}
			return fmt.Errorf("ssh port did not return")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func Fingerprint(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

// ParseSocksProxy accepts "host:port" or "[ipv6]:port". Credentials in the value are rejected.
func ParseSocksProxy(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.Contains(raw, "://") || strings.Contains(raw, "@") || strings.ContainsAny(raw, " \t") {
		return "", fmt.Errorf("socks proxy must be host:port without credentials")
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" {
		return "", fmt.Errorf("socks proxy must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("socks proxy must be host:port")
	}
	return net.JoinHostPort(host, port), nil
}

func (c *Client) Dial(ctx context.Context, opts ConnectOpts) (*ssh.Client, string, error) {
	release := c.acquire(opts.Host)
	defer release()

	var auth []ssh.AuthMethod
	if len(opts.PrivateKey) > 0 {
		var signer ssh.Signer
		var err error
		if opts.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(opts.PrivateKey, []byte(opts.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(opts.PrivateKey)
		}
		if err != nil {
			return nil, "", fmt.Errorf("parse key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if opts.Password != "" {
		auth = append(auth, ssh.Password(opts.Password))
	}
	if len(auth) == 0 {
		return nil, "", errors.New("no auth method")
	}

	var acceptedFP string
	hostKeyCb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := Fingerprint(key)
		acceptedFP = fp
		if opts.KnownFP == "" {
			if opts.PendingOK {
				return nil
			}
			if opts.OnPending != nil {
				opts.OnPending(fp)
			}
			return ErrHostKeyUnknown
		}
		if fp != opts.KnownFP {
			return ErrHostKeyMismatch
		}
		return nil
	}

	addr := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))
	var conn net.Conn
	if opts.Jump != nil {
		if opts.Jump.Port == 0 {
			opts.Jump.Port = 22
		}
		jumpOpts := ConnectOpts{
			Host: opts.Jump.Host, Port: opts.Jump.Port, User: opts.Jump.User,
			Password: opts.Jump.Password, PrivateKey: opts.Jump.PrivateKey,
			Passphrase: opts.Jump.Passphrase, KnownFP: opts.Jump.KnownFP,
			SocksProxy: opts.Jump.SocksProxy,
		}
		jc, _, err := c.Dial(ctx, jumpOpts)
		if err != nil {
			return nil, "", fmt.Errorf("jump %s: %w", opts.Jump.Host, err)
		}
		raw, err := jc.Dial("tcp", addr)
		if err != nil {
			_ = jc.Close()
			return nil, "", err
		}
		conn = &jumpConn{Conn: raw, jump: jc}
	} else if opts.SocksProxy != "" {
		base := &net.Dialer{Timeout: c.cfg.DialTimeout}
		dialer, err := proxy.SOCKS5("tcp", opts.SocksProxy, nil, base)
		if err != nil {
			return nil, "", err
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			conn, err = cd.DialContext(ctx, "tcp", addr)
		} else {
			conn, err = dialer.Dial("tcp", addr)
		}
		if err != nil {
			return nil, "", err
		}
	} else {
		d := net.Dialer{Timeout: c.cfg.DialTimeout}
		var err error
		conn, err = d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, "", err
		}
	}
	_ = conn.SetDeadline(time.Now().Add(c.cfg.DialTimeout))

	sshCfg := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCb,
		Timeout:         c.cfg.DialTimeout,
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
	if err != nil {
		_ = conn.Close()
		return nil, acceptedFP, err
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(cc, chans, reqs)
	return client, acceptedFP, nil
}

func (c *Client) Run(ctx context.Context, opts ConnectOpts, command string) (stdout, stderr string, fp string, err error) {
	client, fp, err := c.Dial(ctx, opts)
	if err != nil {
		return "", "", fp, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", "", fp, err
	}
	defer session.Close()

	var outBuf, errBuf limitedBuffer
	outBuf.max = c.cfg.MaxOutput
	errBuf.max = c.cfg.MaxOutput
	session.Stdout = &outBuf
	session.Stderr = &errBuf

	cmdCtx, cancel := context.WithTimeout(ctx, c.cfg.CmdTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case <-cmdCtx.Done():
		_ = session.Close()
		return outBuf.String(), errBuf.String(), fp, cmdCtx.Err()
	case err := <-done:
		if outBuf.overflow || errBuf.overflow {
			return outBuf.String(), errBuf.String(), fp, ErrOutputTooLarge
		}
		return outBuf.String(), errBuf.String(), fp, err
	}
}

type limitedBuffer struct {
	buf      bytes.Buffer
	max      int64
	overflow bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if int64(l.buf.Len())+int64(len(p)) > l.max {
		l.overflow = true
		remain := l.max - int64(l.buf.Len())
		if remain > 0 {
			_, _ = l.buf.Write(p[:remain])
		}
		return len(p), nil
	}
	return l.buf.Write(p)
}

func (l *limitedBuffer) String() string { return l.buf.String() }

type jumpConn struct {
	net.Conn
	jump *ssh.Client
}

func (j *jumpConn) Close() error {
	err := j.Conn.Close()
	_ = j.jump.Close()
	return err
}

// GenerateEd25519Key returns OpenSSH private key PEM and public key line.
func GenerateEd25519Key(comment string) (privPEM, pubLine []byte, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, nil, err
	}
	pub := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if comment != "" {
		pub = append(bytes.TrimSpace(pub), ' ')
		pub = append(pub, []byte(comment)...)
		pub = append(pub, '\n')
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		// fallback: use golang.org/x/crypto/ssh doesn't always expose MarshalPrivateKey in older versions
		return marshalEd25519OpenSSH(priv, comment)
	}
	privPEM = pem.EncodeToMemory(block)
	return privPEM, pub, nil
}

func marshalEd25519OpenSSH(priv ed25519.PrivateKey, comment string) ([]byte, []byte, error) {
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, nil, err
	}
	pub := ssh.MarshalAuthorizedKey(signer.PublicKey())
	// Use ssh.MarshalPrivateKey if available; otherwise generate via Parse path
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(block), pub, nil
}
