package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestShortSSHSession spins a localhost SSH server and runs a one-shot command
// with host-key pinning — covers acceptance "SSH integration test" without a real VPS.
func TestShortSSHSession(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(signer.PublicKey())

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "ops" && string(pass) == "test-pass" {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			tcp, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSHSession(tcp, cfg)
		}
	}()

	client := New(Config{DialTimeout: 3 * time.Second, CmdTimeout: 5 * time.Second, MaxOutput: 1 << 20, MaxPerHost: 2})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, err = client.Dial(ctx, ConnectOpts{
		Host: "127.0.0.1", Port: port, User: "ops", Password: "test-pass",
	})
	if err == nil || (!errors.Is(err, ErrHostKeyUnknown) && !strings.Contains(err.Error(), ErrHostKeyUnknown.Error())) {
		t.Fatalf("want unknown host key, got %v", err)
	}

	out, stderr, _, err := client.Run(ctx, ConnectOpts{
		Host: "127.0.0.1", Port: port, User: "ops", Password: "test-pass", KnownFP: fp,
	}, "echo vpshub-ok")
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr)
	}
	if !strings.Contains(out, "vpshub-ok") {
		t.Fatalf("out=%q", out)
	}

	_, _, err = client.Dial(ctx, ConnectOpts{
		Host: "127.0.0.1", Port: port, User: "ops", Password: "test-pass",
		KnownFP: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})
	if err == nil || (!errors.Is(err, ErrHostKeyMismatch) && !strings.Contains(err.Error(), ErrHostKeyMismatch.Error())) {
		t.Fatalf("want mismatch, got %v", err)
	}
}

func serveSSHSession(tcp net.Conn, cfg *ssh.ServerConfig) {
	defer tcp.Close()
	conn, chans, reqs, err := ssh.NewServerConn(tcp, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			return
		}
		go func(ch ssh.Channel, requests <-chan *ssh.Request) {
			defer ch.Close()
			for req := range requests {
				switch req.Type {
				case "exec":
					if len(req.Payload) < 4 {
						_ = req.Reply(false, nil)
						continue
					}
					n := binary.BigEndian.Uint32(req.Payload[:4])
					if int(4+n) > len(req.Payload) {
						_ = req.Reply(false, nil)
						continue
					}
					cmd := string(req.Payload[4 : 4+n])
					_ = req.Reply(true, nil)
					if cmd == "echo vpshub-ok" {
						_, _ = io.WriteString(ch, "vpshub-ok\n")
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					} else {
						_, _ = io.WriteString(ch.Stderr(), "unsupported\n")
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
					}
					return
				case "shell", "pty-req", "env":
					_ = req.Reply(true, nil)
				default:
					_ = req.Reply(false, nil)
				}
			}
		}(ch, requests)
	}
}
