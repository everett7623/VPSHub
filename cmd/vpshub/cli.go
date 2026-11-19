package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/panelboot"
)

func runCLI(cmd string, args []string) error {
	switch cmd {
	case "status":
		return cmdStatus(args)
	case "password":
		return cmdPassword(args)
	case "restart":
		return cmdRestart()
	case "bootstrap":
		return cmdBootstrap(args)
	case "restore-db":
		return cmdRestoreDB(args)
	default:
		return fmt.Errorf("unknown command %s", cmd)
	}
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		port = cfg.Listen
	}
	base := cfg.BasePath
	if base == "" {
		base = "/"
	}
	fmt.Printf("listen: %s\nport: %s\nbase_path: %s\ntls: %s\nbasic_auth: %s\nunit: %s\n",
		cfg.Listen, port, base, onOff(cfg.TLSEnabled()), onOff(cfg.BasicAuthEnabled()), unitState())
	return nil
}

func cmdPassword(args []string) error {
	fs := flag.NewFlagSet("password", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	user, pass, err := panelboot.ResetPassword(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("username: %s\npassword: %s\nmust_change_password: true\n", user, pass)
	fmt.Fprintln(os.Stderr, "password printed once; store it offline")
	return nil
}

func cmdRestart() error {
	if !isRoot() {
		fmt.Println("sudo systemctl restart vpshub")
		return nil
	}
	c := exec.Command("systemctl", "restart", "vpshub")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func cmdBootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := panelboot.Bootstrap(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Print(panelboot.Format(res))
	return nil
}

// cmdRestoreDB swaps data/vpshub.db.restored into place after a panel backup restore.
// Stop the panel first so SQLite files are not open.
func cmdRestoreDB(args []string) error {
	fs := flag.NewFlagSet("restore-db", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	confirm := fs.Bool("yes", false, "confirm replace of vpshub.db")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf("refusing without -yes (stop vpshub first, then: vpshub restore-db -yes)")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	return panelboot.ApplyRestoredDB(cfg.DataDir)
}

func defaultConfigPath() string {
	const system = "/etc/vpshub/config.yaml"
	if st, err := os.Stat(system); err == nil && !st.IsDir() {
		return system
	}
	return "config.yaml"
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func unitState() string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "unknown"
	}
	out, _ := exec.Command("systemctl", "is-active", "vpshub").Output()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "unknown"
	}
	return s
}
