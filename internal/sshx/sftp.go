package sshx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/pkg/sftp"
)

var ErrSFTPDisabled = errors.New("sftp disabled")

// MaxUploadBytes is the SFTP read and write cap.
const MaxUploadBytes int64 = 10 << 20

// DistributeMaxHosts matches the fleet batch cap.
const DistributeMaxHosts = 40

// SFTPSession wraps a short-lived SFTP client with path restrictions.
type SFTPSession struct {
	client *sftp.Client
	root   string
	maxSz  int64
}

func OpenSFTP(ctx context.Context, c *Client, opts ConnectOpts, root string, maxBytes int64) (*SFTPSession, error) {
	if maxBytes <= 0 {
		maxBytes = MaxUploadBytes
	}
	if root == "" {
		root = "/"
	}
	sshClient, _, err := c.Dial(ctx, opts)
	if err != nil {
		return nil, err
	}
	sc, err := sftp.NewClient(sshClient)
	if err != nil {
		_ = sshClient.Close()
		return nil, err
	}
	return &SFTPSession{client: sc, root: root, maxSz: maxBytes}, nil
}

func (s *SFTPSession) Close() error {
	return s.client.Close()
}

func (s *SFTPSession) resolve(p string) (string, error) {
	return JailPath(s.root, p)
}

// JailPath joins rel under root and refuses a result outside that root.
func JailPath(root, rel string) (string, error) {
	root = path.Clean(root)
	if root == "." || root == "" || !strings.HasPrefix(root, "/") {
		return "", fmt.Errorf("path outside allowed root")
	}
	clean := path.Clean("/" + strings.TrimPrefix(rel, "/"))
	if !strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("path outside allowed root")
	}
	full := path.Join(root, strings.TrimPrefix(clean, "/"))
	if !pathInside(root, full) {
		return "", fmt.Errorf("path outside allowed root")
	}
	return full, nil
}

// RequireSFTPRoot jails rel under a configured directory. The filesystem root is refused.
func RequireSFTPRoot(root, rel string) (string, error) {
	root = path.Clean(root)
	if root == "/" || root == "." || !strings.HasPrefix(root, "/") {
		return "", fmt.Errorf("sftp_root required")
	}
	full, err := JailPath(root, rel)
	if err != nil {
		return "", err
	}
	if full == root {
		return "", fmt.Errorf("file required")
	}
	return full, nil
}

func pathInside(root, full string) bool {
	if root == "/" {
		return strings.HasPrefix(full, "/")
	}
	return full == root || strings.HasPrefix(full, root+"/")
}

func (s *SFTPSession) Download(remote string, w io.Writer) error {
	full, err := s.resolve(remote)
	if err != nil {
		return err
	}
	f, err := s.client.Open(full)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.CopyN(w, f, s.maxSz+1)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrOutputTooLarge
}

type FileEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
	Mode  string `json:"mode"`
}

func (s *SFTPSession) List(dir string) ([]FileEntry, error) {
	if dir == "" {
		dir = "."
	}
	full, err := s.resolve(dir)
	if err != nil {
		return nil, err
	}
	infos, err := s.client.ReadDir(full)
	if err != nil {
		return nil, err
	}
	out := make([]FileEntry, 0, len(infos))
	for _, info := range infos {
		out = append(out, FileEntry{
			Name: info.Name(), Size: info.Size(), IsDir: info.IsDir(), Mode: info.Mode().String(),
		})
	}
	return out, nil
}

func (s *SFTPSession) Upload(remote string, r io.Reader, size int64) (string, error) {
	if size > s.maxSz {
		return "", ErrOutputTooLarge
	}
	full, err := s.resolve(remote)
	if err != nil {
		return "", err
	}
	f, err := s.client.Create(full)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(f, io.TeeReader(io.LimitReader(r, s.maxSz), h))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

const textMax = 64 << 10

// ReadText returns a small text file and its SHA256. Binary files are rejected.
func (s *SFTPSession) ReadText(remote string) (string, string, error) {
	full, err := s.resolve(remote)
	if err != nil {
		return "", "", err
	}
	f, err := s.client.Open(full)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, textMax+1))
	if err != nil {
		return "", "", err
	}
	text, sum, err := InspectText(buf)
	return text, sum, err
}

// ReadFile returns a small file under the session root and its SHA256.
func (s *SFTPSession) ReadFile(remote string) ([]byte, string, error) {
	full, err := s.resolve(remote)
	if err != nil {
		return nil, "", err
	}
	st, err := s.client.Stat(full)
	if err != nil {
		return nil, "", err
	}
	if st.IsDir() {
		return nil, "", fmt.Errorf("not a file")
	}
	if st.Size() > s.maxSz {
		return nil, "", ErrOutputTooLarge
	}
	f, err := s.client.Open(full)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, s.maxSz+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(buf)) > s.maxSz {
		return nil, "", ErrOutputTooLarge
	}
	sum := sha256.Sum256(buf)
	return buf, hex.EncodeToString(sum[:]), nil
}

// Remove deletes a file under the session root. Directories are refused.
func (s *SFTPSession) Remove(remote string) error {
	full, err := s.resolve(remote)
	if err != nil {
		return err
	}
	st, err := s.client.Stat(full)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("not a file")
	}
	return s.client.Remove(full)
}

func (s *SFTPSession) WriteText(remote, content string) (string, error) {
	buf := []byte(content)
	if _, _, err := InspectText(buf); err != nil {
		return "", err
	}
	full, err := s.resolve(remote)
	if err != nil {
		return "", err
	}
	f, err := s.client.Create(full)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(buf); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// InspectText accepts a small file with no NUL bytes.
func InspectText(buf []byte) (string, string, error) {
	if int64(len(buf)) > textMax {
		return "", "", ErrOutputTooLarge
	}
	if bytes.IndexByte(buf, 0) >= 0 {
		return "", "", fmt.Errorf("not a text file")
	}
	sum := sha256.Sum256(buf)
	return string(buf), hex.EncodeToString(sum[:]), nil
}
