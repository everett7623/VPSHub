package backup

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// ConfigBackupKeep is how many newest config archives stay on the remote host.
const ConfigBackupKeep = 5

var stampRE = regexp.MustCompile(`^[0-9]{14}$`)

// ConfigBackupPaths are the only remote trees a config backup may archive.
// Absolute fixed paths only — no user-supplied paths, no shell injection.
var ConfigBackupPaths = []string{
	"/etc/nginx",
	"/etc/caddy",
	"/etc/letsencrypt",
	"/etc/systemd/system",
	"/etc/docker",
	"/etc/wireguard",
	"/etc/komari",
	"/etc/komari-lite",
	"/usr/local/etc/xray",
	"/etc/xray",
	"/etc/sing-box",
	"/etc/hysteria",
	"/etc/shadowsocks-rust",
	"/etc/anytls",
	"/opt/nezha",
}

// ArchiveBase returns a unique .tgz basename for a whitelist path (no extension).
func ArchiveBase(p string) string {
	return strings.ReplaceAll(strings.Trim(strings.TrimPrefix(path.Clean(p), "/"), "/"), "/", "-")
}

// PathAllowed reports whether p is the fixed whitelist or a safe subpath of it.
func PathAllowed(p string) bool {
	if validateFixedPath(p) != nil {
		return false
	}
	for _, w := range ConfigBackupPaths {
		if p == w || strings.HasPrefix(p, w+"/") {
			return true
		}
	}
	return false
}

// MergeConfigPaths returns whitelist ∪ extras (validated, deduped, extras must be under whitelist).
func MergeConfigPaths(extra []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !PathAllowed(p) || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range ConfigBackupPaths {
		add(p)
	}
	for _, p := range extra {
		add(p)
	}
	return out
}

// ConfigBackupPlan archives the fixed whitelist into /var/backups/vpshub/<stamp>/.
func ConfigBackupPlan(dryRun bool) (string, error) {
	return ConfigBackupPlanWith(nil, dryRun)
}

// ConfigBackupPlanWith archives MergeConfigPaths(extra). Missing paths are skipped.
func ConfigBackupPlanWith(extra []string, dryRun bool) (string, error) {
	paths := MergeConfigPaths(extra)
	for _, p := range paths {
		if err := validateFixedPath(p); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	if dryRun {
		b.WriteString("echo 'dry-run config backup'\n")
		b.WriteString("echo 'dest /var/backups/vpshub/<stamp>/'\n")
		for _, p := range paths {
			fmt.Fprintf(&b, "echo 'path %s'\n", p)
		}
		fmt.Fprintf(&b, "echo 'keep %d'\n", ConfigBackupKeep)
		return b.String(), nil
	}
	b.WriteString("set -euo pipefail\n")
	b.WriteString("root=/var/backups/vpshub\n")
	b.WriteString("stamp=$(date +%Y%m%d%H%M%S)\n")
	b.WriteString("case \"$stamp\" in\n")
	b.WriteString("  [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n")
	b.WriteString("  *) echo 'bad stamp'; exit 1 ;;\n")
	b.WriteString("esac\n")
	b.WriteString("dest=\"$root/$stamp\"\n")
	b.WriteString("mkdir -p \"$dest\"\n")
	b.WriteString("archived=0\n")
	var markers []string
	for _, p := range paths {
		base := ArchiveBase(p)
		dir := path.Dir(p)
		leaf := path.Base(p)
		fmt.Fprintf(&b, "if [ -e %s ]; then\n", quote(p))
		fmt.Fprintf(&b, "  tar -czf \"$dest\"/%s.tgz -C %s %s\n", quote(base), quote(dir), quote(leaf))
		fmt.Fprintf(&b, "  echo 'archived %s'\n", p)
		b.WriteString("  archived=1\n")
		b.WriteString("else\n")
		fmt.Fprintf(&b, "  echo 'skip %s'\n", p)
		b.WriteString("fi\n")
		markers = append(markers, fmt.Sprintf("[ ! -f \"$root/$d/%s.tgz\" ]", base))
	}
	b.WriteString("if [ \"$archived\" -eq 0 ]; then\n")
	b.WriteString("  rmdir \"$dest\" || true\n")
	b.WriteString("  echo 'nothing to archive'\n")
	b.WriteString("  exit 0\n")
	b.WriteString("fi\n")
	b.WriteString("echo \"backup $dest\"\n")
	b.WriteString("count=0\n")
	b.WriteString("names=$(ls -1 \"$root\" 2>/dev/null | sort -r || true)\n")
	b.WriteString("for d in $names; do\n")
	b.WriteString("  case \"$d\" in\n")
	b.WriteString("    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n")
	b.WriteString("    *) continue ;;\n")
	b.WriteString("  esac\n")
	fmt.Fprintf(&b, "  if %s; then\n", strings.Join(markers, " && "))
	b.WriteString("    continue\n")
	b.WriteString("  fi\n")
	b.WriteString("  count=$((count+1))\n")
	fmt.Fprintf(&b, "  if [ \"$count\" -gt %d ]; then\n", ConfigBackupKeep)
	b.WriteString("    rm -rf \"$root/$d\"\n")
	b.WriteString("    echo \"pruned $d\"\n")
	b.WriteString("  fi\n")
	b.WriteString("done\n")
	return b.String(), nil
}

// ConfigRestorePlan restores known .tgz archives from /var/backups/vpshub/<stamp>/.
func ConfigRestorePlan(stamp string, dryRun bool) (string, error) {
	return ConfigRestorePlanWith(stamp, nil, dryRun)
}

// ConfigRestorePlanWith restores MergeConfigPaths(extra) archives for stamp.
func ConfigRestorePlanWith(stamp string, extra []string, dryRun bool) (string, error) {
	if !stampRE.MatchString(stamp) {
		return "", fmt.Errorf("invalid stamp")
	}
	paths := MergeConfigPaths(extra)
	for _, p := range paths {
		if err := validateFixedPath(p); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	src := "/var/backups/vpshub/" + stamp
	if dryRun {
		b.WriteString("echo 'dry-run config restore'\n")
		fmt.Fprintf(&b, "echo 'stamp %s'\n", stamp)
		fmt.Fprintf(&b, "echo 'src %s'\n", src)
		for _, p := range paths {
			base := ArchiveBase(p)
			fmt.Fprintf(&b, "echo 'would restore %s from %s.tgz'\n", p, base)
		}
		return b.String(), nil
	}
	b.WriteString("set -euo pipefail\n")
	fmt.Fprintf(&b, "src=%s\n", quote(src))
	b.WriteString("if [ ! -d \"$src\" ]; then\n")
	b.WriteString("  echo 'stamp directory missing'\n")
	b.WriteString("  exit 1\n")
	b.WriteString("fi\n")
	b.WriteString("restored=0\n")
	for _, p := range paths {
		base := ArchiveBase(p)
		parent := path.Dir(p)
		fmt.Fprintf(&b, "if [ -f \"$src\"/%s.tgz ]; then\n", quote(base))
		fmt.Fprintf(&b, "  mkdir -p %s\n", quote(parent))
		fmt.Fprintf(&b, "  tar -xzf \"$src\"/%s.tgz -C %s\n", quote(base), quote(parent))
		fmt.Fprintf(&b, "  echo 'restored %s'\n", p)
		b.WriteString("  restored=1\n")
		b.WriteString("else\n")
		fmt.Fprintf(&b, "  echo 'skip %s'\n", p)
		b.WriteString("fi\n")
	}
	b.WriteString("if [ \"$restored\" -eq 0 ]; then\n")
	b.WriteString("  echo 'nothing to restore'\n")
	b.WriteString("  exit 1\n")
	b.WriteString("fi\n")
	b.WriteString("echo 'restore done'\n")
	return b.String(), nil
}

func validateFixedPath(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return fmt.Errorf("invalid backup path")
	}
	if strings.ContainsAny(p, ";&|`$<>'\"\\ \n\t") {
		return fmt.Errorf("invalid backup path")
	}
	if path.Clean(p) != p {
		return fmt.Errorf("invalid backup path")
	}
	return nil
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
