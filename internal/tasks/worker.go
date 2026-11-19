package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/evenfrank/vpshub/internal/config"
	"github.com/evenfrank/vpshub/internal/sshx"
	"github.com/evenfrank/vpshub/internal/store"
)

type Executor func(ctx context.Context, item *store.TaskItem, task *store.Task, vps *store.VPS) (result string, err error)

type Worker struct {
	DB        *store.DB
	Cfg       *config.Config
	SSH       *sshx.Client
	Log       *slog.Logger
	executors map[string]Executor
	cancel    map[string]context.CancelFunc
	mu        sync.Mutex
	vpsLocks  sync.Map
	// OnItemFailed is optional; called after a task item is marked failed (no secrets).
	OnItemFailed func(vpsID int64, taskID, taskType string)
}

func NewWorker(db *store.DB, cfg *config.Config, sshClient *sshx.Client, log *slog.Logger) *Worker {
	w := &Worker{
		DB:        db,
		Cfg:       cfg,
		SSH:       sshClient,
		Log:       log,
		executors: map[string]Executor{},
		cancel:    map[string]context.CancelFunc{},
	}
	w.Register("shell", w.execShell)
	w.Register("scan", w.execScanStub)
	return w
}

func (w *Worker) Register(typ string, fn Executor) {
	w.executors[typ] = fn
}

func (w *Worker) Start(ctx context.Context) {
	_ = w.DB.RecoverRunningTasks()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.poll(ctx)
		}
	}
}

func (w *Worker) poll(ctx context.Context) {
	tasks, err := w.DB.ListPendingTasks()
	if err != nil {
		w.Log.Error("list pending tasks", "err", err)
		return
	}
	for _, t := range tasks {
		if t.Status == "pending" {
			go w.runTask(ctx, t)
		}
	}
}

func (w *Worker) Cancel(taskID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, ok := w.cancel[taskID]; ok {
		c()
	}
	_ = w.DB.UpdateTaskStatus(taskID, "cancelled")
}

func (w *Worker) runTask(parent context.Context, t *store.Task) {
	w.mu.Lock()
	if _, running := w.cancel[t.ID]; running {
		w.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel[t.ID] = cancel
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.cancel, t.ID)
		w.mu.Unlock()
		cancel()
	}()

	_ = w.DB.UpdateTaskStatus(t.ID, "running")
	items, err := w.DB.ListTaskItems(t.ID)
	if err != nil {
		_ = w.DB.UpdateTaskStatus(t.ID, "failed")
		return
	}

	var canary []int64
	_ = json.Unmarshal([]byte(t.CanaryVPSIds), &canary)
	canarySet := map[int64]bool{}
	for _, id := range canary {
		canarySet[id] = true
	}

	conc := t.Concurrency
	if conc <= 0 {
		conc = w.Cfg.TaskMaxConc
	}

	// Phase: canary first
	var canaryItems, rest []*store.TaskItem
	for _, it := range items {
		if canarySet[it.VPSID] {
			canaryItems = append(canaryItems, it)
		} else {
			rest = append(rest, it)
		}
	}

	failed, total := 0, 0
	runBatch := func(batch []*store.TaskItem, limit int) bool {
		sem := make(chan struct{}, limit)
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, it := range batch {
			select {
			case <-ctx.Done():
				return false
			default:
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(it *store.TaskItem) {
				defer wg.Done()
				defer func() { <-sem }()
				ok := w.runItem(ctx, t, it)
				mu.Lock()
				total++
				if !ok {
					failed++
				}
				mu.Unlock()
			}(it)
		}
		wg.Wait()
		if t.FailThreshold > 0 && total > 0 && float64(failed)/float64(total) >= t.FailThreshold {
			if taskOnFail(t.Payload) == "continue" {
				w.Log.Info("fail threshold reached; continuing", "task", t.ID, "failed", failed, "total", total)
				return true
			}
			_ = w.DB.UpdateTaskStatus(t.ID, "failed")
			return false
		}
		return true
	}

	if len(canaryItems) > 0 {
		if !runBatch(canaryItems, 1) {
			return
		}
	}

	if t.RollBatch > 0 {
		for i := 0; i < len(rest); i += t.RollBatch {
			end := i + t.RollBatch
			if end > len(rest) {
				end = len(rest)
			}
			if !runBatch(rest[i:end], conc) {
				return
			}
		}
	} else {
		if !runBatch(rest, conc) {
			return
		}
	}

	items, _ = w.DB.ListTaskItems(t.ID)
	status := "success"
	for _, it := range items {
		if it.Status == "failed" || it.Status == "timeout" {
			status = "failed"
			break
		}
		if it.Status == "cancelled" {
			status = "cancelled"
		}
	}
	_ = w.DB.UpdateTaskStatus(t.ID, status)
}

func (w *Worker) runItem(ctx context.Context, t *store.Task, it *store.TaskItem) bool {
	// Per-VPS mutex for mutating tasks
	lockKey := fmt.Sprintf("%d", it.VPSID)
	for {
		if _, loaded := w.vpsLocks.LoadOrStore(lockKey, true); !loaded {
			break
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
		}
	}
	defer w.vpsLocks.Delete(lockKey)

	now := time.Now()
	it.Status = "running"
	it.StartedAt = &now
	_ = w.DB.UpdateTaskItem(it)

	vps, err := w.DB.GetVPS(it.VPSID)
	if err != nil {
		it.Status = "failed"
		it.Error = err.Error()
		fin := time.Now()
		it.FinishedAt = &fin
		_ = w.DB.UpdateTaskItem(it)
		if w.OnItemFailed != nil {
			w.OnItemFailed(it.VPSID, t.ID, t.Type)
		}
		return false
	}
	if vps.Environment == "production" && t.Concurrency > w.Cfg.TaskProdConc {
		// already limited by caller; still respect prod op_mode
	}
	if t.Type != "scan" {
		risk := t.RiskLevel
		if t.Type == "config_backup" || t.Type == "config_restore" {
			risk = "high"
		}
		if err := store.AllowChange(vps.OpMode, risk); err != nil {
			it.Status = "skipped"
			it.Result = "op_mode_blocks"
			fin := time.Now()
			it.FinishedAt = &fin
			_ = w.DB.UpdateTaskItem(it)
			return true
		}
	}

	exec := w.executors[t.Type]
	if exec == nil {
		it.Status = "failed"
		it.Error = "unknown task type: " + t.Type
		fin := time.Now()
		it.FinishedAt = &fin
		_ = w.DB.UpdateTaskItem(it)
		if w.OnItemFailed != nil {
			w.OnItemFailed(it.VPSID, t.ID, t.Type)
		}
		return false
	}

	timeout := time.Duration(t.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(w.Cfg.SSHCmdTimeout)
	}
	maxTries := retryTries(t.RetryMax)

	var lastErr error
	var result string
	for try := 0; try < maxTries; try++ {
		it.Attempt++
		_ = w.DB.UpdateTaskItem(it)
		itemCtx, cancel := context.WithTimeout(ctx, timeout)
		result, lastErr = exec(itemCtx, it, t, vps)
		cancel()
		if lastErr == nil {
			fin := time.Now()
			it.FinishedAt = &fin
			it.Status = "success"
			it.Result = result
			it.Error = ""
			_ = w.DB.UpdateTaskItem(it)
			return true
		}
		if try+1 >= maxTries {
			break
		}
		backoff := time.Duration(try+1) * time.Second
		select {
		case <-ctx.Done():
			fin := time.Now()
			it.FinishedAt = &fin
			it.Status = "cancelled"
			it.Error = ctx.Err().Error()
			_ = w.DB.UpdateTaskItem(it)
			return false
		case <-time.After(backoff):
		}
	}

	fin := time.Now()
	it.FinishedAt = &fin
	it.Status = "failed"
	if lastErr != nil {
		it.Error = lastErr.Error()
	}
	_ = w.DB.UpdateTaskItem(it)
	if w.OnItemFailed != nil {
		w.OnItemFailed(it.VPSID, t.ID, t.Type)
	}
	return false
}

type shellPayload struct {
	Command string `json:"command"`
}

// retryTries maps retry_max (extra attempts) to total tries, capped at 10.
func retryTries(retryMax int) int {
	n := retryMax + 1
	if n < 1 {
		n = 1
	}
	if n > 10 {
		n = 10
	}
	return n
}

// taskOnFail reads payload.on_fail: "pause" (default) stops the fleet when the
// fail threshold is hit; "continue" keeps rolling remaining hosts.
func taskOnFail(payload string) string {
	var p struct {
		OnFail string `json:"on_fail"`
	}
	_ = json.Unmarshal([]byte(payload), &p)
	if strings.EqualFold(p.OnFail, "continue") {
		return "continue"
	}
	return "pause"
}

func (w *Worker) execShell(ctx context.Context, item *store.TaskItem, task *store.Task, vps *store.VPS) (string, error) {
	var p shellPayload
	_ = json.Unmarshal([]byte(task.Payload), &p)
	if p.Command == "" {
		return "", fmt.Errorf("empty command")
	}
	if task.DryRun {
		msg := fmt.Sprintf("[dry-run] would run on %s: %s", vps.Host, p.Command)
		_ = w.DB.AppendTaskItemLog(item.ID, msg)
		return msg, nil
	}
	// Actual SSH execution is wired by API layer via credential injection — stub marks need unlock
	return "", fmt.Errorf("shell executor requires SSH credentials; use API-bound runner")
}

func (w *Worker) execScanStub(ctx context.Context, item *store.TaskItem, task *store.Task, vps *store.VPS) (string, error) {
	_ = w.DB.AppendTaskItemLog(item.ID, "scan queued — use /api/vps/:id/scan for credentialed scan")
	return "delegated", nil
}

// BindSSHRunner replaces shell/scan with credential-aware runners.
func (w *Worker) BindSSHRunner(run func(ctx context.Context, item *store.TaskItem, task *store.Task, vps *store.VPS) (string, error)) {
	w.Register("shell", run)
	w.Register("script", run)
	w.Register("scan", run)
	w.Register("upgrade", run)
	w.Register("sysupgrade", run)
	w.Register("config_backup", run)
	w.Register("config_restore", run)
}
