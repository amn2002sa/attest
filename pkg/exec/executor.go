package exec

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/provnai/attest/pkg/policy"
)

// ReversibleAction represents an action that can be reversed
type ReversibleAction struct {
	ID             string     `json:"id"`
	AttestationID  string     `json:"attestationId"`
	Command        string     `json:"command"`
	WorkingDir     string     `json:"workingDir"`
	BackupPath     string     `json:"backupPath"`
	ReverseCommand string     `json:"reverseCommand"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"createdAt"`
	RolledBackAt   *time.Time `json:"rolledBackAt,omitempty"`
}

// ReversibleStatus represents the status of a reversible action
type ReversibleStatus string

const (
	StatusPending    ReversibleStatus = "pending"
	StatusExecuted   ReversibleStatus = "executed"
	StatusRolledBack ReversibleStatus = "rolled_back"
	StatusFailed     ReversibleStatus = "failed"
)

// BackupType represents the type of backup to create
type BackupType string

const (
	BackupTypeFile BackupType = "file"
	BackupTypeDir  BackupType = "directory"
	BackupTypeDB   BackupType = "database"
	BackupTypeNone BackupType = "none"
)

// ExecuteOptions contains options for reversible execution
type ExecuteOptions struct {
	Command    string
	WorkingDir string
	Reversible bool
	BackupType BackupType
	IntentID   string
	AgentID    string
	DryRun     bool
}

// ExecuteResult contains the result of execution
type ExecuteResult struct {
	Success          bool
	ActionID         string
	BackupPath       string
	ReverseCommand   string
	Output           string
	Error            error
	PolicyViolations []string
}

// BackupManager handles creating and restoring backups
type BackupManager struct {
	backupDir string
}

// NewBackupManager creates a new backup manager
func NewBackupManager(backupDir string) (*BackupManager, error) {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}
	return &BackupManager{backupDir: backupDir}, nil
}

// CreateBackup creates a backup of a target
func (m *BackupManager) CreateBackup(target string, backupType BackupType) (string, error) {
	// Generate unique backup name
	timestamp := time.Now().Format("20060102-150405")
	hash := sha256.Sum256([]byte(target + timestamp))
	backupName := fmt.Sprintf("backup-%s-%x", timestamp, hash[:8])
	backupPath := filepath.Join(m.backupDir, backupName)

	switch backupType {
	case BackupTypeFile:
		return m.backupFile(target, backupPath)
	case BackupTypeDir:
		return m.backupDirectory(target, backupPath)
	case BackupTypeDB:
		return m.backupDatabase(target, backupPath)
	default:
		return "", nil
	}
}

// backupFile creates a backup of a single file
func (m *BackupManager) backupFile(target, backupPath string) (string, error) {
	data, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	return backupPath, nil
}

// backupDirectory creates a backup of a directory
func (m *BackupManager) backupDirectory(target, backupPath string) (string, error) {
	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup dir: %w", err)
	}

	if err := copyDir(target, backupPath); err != nil {
		return "", fmt.Errorf("failed to copy directory: %w", err)
	}

	return backupPath, nil
}

// backupDatabase creates a backup of a database
func (m *BackupManager) backupDatabase(target, backupPath string) (string, error) {
	// For SQLite, copy the database file
	if isSQLite(target) {
		return m.backupFile(target, backupPath)
	}

	// For other databases, create a SQL dump (Planned for v1.1)
	return "", fmt.Errorf("database type not yet supported for backup")
}

// RestoreBackup restores a backup
func (m *BackupManager) RestoreBackup(backupPath, originalPath string) error {
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupPath)
	}

	// Remove original if it exists
	if _, err := os.Stat(originalPath); err == nil {
		if err := os.RemoveAll(originalPath); err != nil {
			return fmt.Errorf("failed to remove original: %w", err)
		}
	}

	// Move backup to original location
	if err := os.Rename(backupPath, originalPath); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	return nil
}

// dangerousPatterns contains regex patterns for dangerous commands
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[;&|]`),                                   // Command chaining
	regexp.MustCompile(`\$\(.*\)`),                                // Command substitution
	regexp.MustCompile("``"),                                      // Backtick execution
	regexp.MustCompile(`>(>?)\s*/dev/(null|zero|random|urandom)`), // Dangerous redirects
	regexp.MustCompile(`rm\s+-rf\s+/`),                            // Root deletion
	regexp.MustCompile(`:\(\)\s*\{\s*:\|:\s*\}&`),                 // Fork bomb
	regexp.MustCompile(`wget\s+.*\|\s*(sh|bash)`),                 // Pipe to shell
	regexp.MustCompile(`curl\s+.*\|\s*(sh|bash)`),                 // Pipe to shell
	regexp.MustCompile(`eval\s*\(`),                               // Eval
	regexp.MustCompile(`exec\s*\(`),                               // Exec
}

// ValidateCommand checks if a command is safe to execute
func ValidateCommand(command string) error {
	if len(command) == 0 {
		return fmt.Errorf("command cannot be empty")
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(command) {
			return fmt.Errorf("command contains dangerous pattern: %s", pattern.String())
		}
	}

	// Check command length
	if len(command) > 10000 {
		return fmt.Errorf("command too long (max 10000 characters)")
	}

	return nil
}

// SanitizeCommand sanitizes a command by removing dangerous characters
func SanitizeCommand(command string) string {
	// Remove null bytes
	command = strings.ReplaceAll(command, "\x00", "")

	// Trim whitespace
	command = strings.TrimSpace(command)

	return command
}

type Executor struct {
	backupManager *BackupManager
	policyEngine  *policy.PolicyEngine
}

// NewExecutor creates a new executor
func NewExecutor(backupDir string) (*Executor, error) {
	bm, err := NewBackupManager(backupDir)
	if err != nil {
		return nil, err
	}

	return &Executor{
		backupManager: bm,
		policyEngine:  policy.NewPolicyEngine(),
	}, nil
}

// SetPolicyEngine sets the policy engine
func (e *Executor) SetPolicyEngine(engine *policy.PolicyEngine) {
	e.policyEngine = engine
}

// Execute runs a command with optional reversibility
func (e *Executor) Execute(opts ExecuteOptions) *ExecuteResult {
	// Check policies first
	if e.policyEngine != nil {
		ctx := policy.ActionContext{
			Type:        "command",
			Target:      opts.Command,
			Environment: "development", // Default, could be passed in opts
			AgentID:     opts.AgentID,
			IntentID:    opts.IntentID,
		}
		
		allowed, results := e.policyEngine.ShouldAllow(ctx)
		if !allowed {
			var violations []string
			for _, r := range results {
				if r.Matched && r.Action == policy.PolicyActionBlock {
					violations = append(violations, r.Message)
				}
			}
			return &ExecuteResult{
				Success:          false,
				Error:            fmt.Errorf("policy violation: %s", strings.Join(violations, "; ")),
				PolicyViolations: violations,
			}
		}
	}

	// Validate and sanitize command
	sanitizedCmd := SanitizeCommand(opts.Command)
	if err := ValidateCommand(sanitizedCmd); err != nil {
		return &ExecuteResult{
			Success: false,
			Error:   fmt.Errorf("command validation failed: %w", err),
		}
	}

	// Create action ID
	actionID := generateActionID(sanitizedCmd)

	// Handle reversibility
	var backupPath string
	var reverseCmd string

	if opts.Reversible {
		var err error
		actualBackupType := opts.BackupType
		
		// If working dir is a directory and type is file, upgrade to directory backup
		if info, sErr := os.Stat(opts.WorkingDir); sErr == nil && info.IsDir() && actualBackupType == BackupTypeFile {
			actualBackupType = BackupTypeDir
		}

		backupPath, err = e.backupManager.CreateBackup(opts.WorkingDir, actualBackupType)
		if err != nil {
			return &ExecuteResult{
				Success: false,
				Error:   fmt.Errorf("backup failed: %w", err),
			}
		}
		reverseCmd = e.generateReverseCommand(sanitizedCmd, backupPath)
	}

	// Dry run
	if opts.DryRun {
		return &ExecuteResult{
			Success:        true,
			ActionID:       actionID,
			BackupPath:     backupPath,
			ReverseCommand: reverseCmd,
			Output:         "[DRY RUN] Command would execute",
		}
	}

	// Execute command
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", sanitizedCmd)
	} else {
		cmd = exec.Command("sh", "-c", sanitizedCmd)
	}
	cmd.Dir = opts.WorkingDir

	output, err := cmd.CombinedOutput()

	if err != nil {
		// Command failed - try to restore backup
		if backupPath != "" {
			if rErr := e.backupManager.RestoreBackup(backupPath, opts.WorkingDir); rErr != nil {
				fmt.Printf("Warning: failed to restore backup after command failure: %v\n", rErr)
			}
		}
		return &ExecuteResult{
			Success:        false,
			ActionID:       actionID,
			BackupPath:     backupPath,
			ReverseCommand: reverseCmd,
			Output:         string(output),
			Error:          err,
		}
	}

	return &ExecuteResult{
		Success:        true,
		ActionID:       actionID,
		BackupPath:     backupPath,
		ReverseCommand: reverseCmd,
		Output:         string(output),
	}
}

// Rollback reverses a previously executed action
func (e *Executor) Rollback(actionID, backupPath, originalPath string) error {
	return e.backupManager.RestoreBackup(backupPath, originalPath)
}

// generateReverseCommand generates the reverse command for rollback
func (e *Executor) generateReverseCommand(command, backupPath string) string {
	if backupPath == "" {
		return ""
	}
	
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("xcopy /E /Y %s .", backupPath)
	}
	return fmt.Sprintf("cp -R %s/* .", backupPath)
}

// generateActionID generates a unique ID for an action
func generateActionID(command string) string {
	data := fmt.Sprintf("exec:%s:%s", command, time.Now().UTC().Format(time.RFC3339))
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("exec:%x", hash[:8])
}

// Helper functions

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(src, path)
		if relPath == "" {
			return nil
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		return copyFile(path, dstPath)
	})
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func isSQLite(path string) bool {
	return len(path) > 3 && path[len(path)-3:] == ".db"
}

// ActionStore stores reversible actions
type ActionStore struct {
	// Database operations will be implemented here
}

// NewActionStore creates a new action store
func NewActionStore() *ActionStore {
	return &ActionStore{}
}

// Save saves a reversible action
func (s *ActionStore) Save(action *ReversibleAction) error {
	// TODO: Implement database save
	return nil
}

// Get retrieves an action by ID
func (s *ActionStore) Get(id string) (*ReversibleAction, error) {
	// TODO: Implement database get
	return nil, nil
}

// List returns actions with optional filtering
func (s *ActionStore) List(agentID, status string, limit int) ([]*ReversibleAction, error) {
	// TODO: Implement database list
	return nil, nil
}
