package cmd

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/provnai/attest/pkg/exec"
	"github.com/provnai/attest/pkg/policy"
	"github.com/provnai/attest/pkg/storage"
)

var (
	execReversible bool
	execIntent     string
	execAgent      string
	execDryRun     bool
	execBackupType string
	execEnv        string
)

func init() {
	execRunCmd.Flags().BoolVar(&execReversible, "reversible", false, "make this execution reversible")
	execRunCmd.Flags().StringVar(&execIntent, "intent", "", "link to an intent ID")
	execRunCmd.Flags().StringVar(&execAgent, "agent", "", "agent ID (required for signing)")
	execRunCmd.Flags().BoolVar(&execDryRun, "dry-run", false, "show what would happen without executing")
	execRunCmd.Flags().StringVar(&execBackupType, "backup", "file", "backup type (file, dir, none)")
	execRunCmd.Flags().StringVar(&execEnv, "env", "development", "environment (development, staging, production)")

	execCmd.AddCommand(execRunCmd)
	execCmd.AddCommand(execRollbackCmd)
	execCmd.AddCommand(execHistoryCmd)
}

var execCmd = &cobra.Command{
	Use:   "exec",
	Short: "Execute reversible commands",
	Long:  `Execute commands with automatic backup and optional reversibility.`,
}

var execRunCmd = &cobra.Command{
	Use:   "run [command...]",
	Short: "Run a reversible command",
	Long: `Execute a command with optional reversibility. Creates automatic backups
for file modifications when --reversible is specified.`,
	Example: `
  # Simple command
  attest exec run "echo hello"

  # Reversible command with backup
  attest exec run --reversible "python migrate.py"

  # Dry run to see what would happen
  attest exec run --dry-run "rm important.txt"

  # With agent identity and intent
  attest exec run --agent aid:1234 --intent int:abcd --reversible "python script.py"`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		command := strings.Join(args, " ")
		if command == "" {
			fmt.Println("Error: command is required")
			os.Exit(1)
		}
		if err := runExecRun(command); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var execRollbackCmd = &cobra.Command{
	Use:   "rollback [id]",
	Short: "Rollback an action",
	Long:  `Reverse a previously executed reversible action.`,
	Example: `
  # Rollback last action
  attest exec rollback last

  # Rollback specific action
  attest exec rollback exec:12345678`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := runExecRollback(args[0]); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var execHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Show execution history",
	Long:  `Show all reversible actions with their status.`,
	Example: `
  # Show history
  attest exec history

  # Show pending rollbacks
  attest exec history --pending`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runExecHistory(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func runExecRun(command string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		workingDir = "."
	}

	backupType := exec.BackupTypeNone
	if execReversible {
		switch execBackupType {
		case "file":
			backupType = exec.BackupTypeFile
		case "dir":
			backupType = exec.BackupTypeDir
		case "none":
			backupType = exec.BackupTypeNone
		default:
			backupType = exec.BackupTypeFile
		}
	}

	executor, err := exec.NewExecutor(cfg.BackupDir)
	if err != nil {
		return fmt.Errorf("failed to create executor: %w", err)
	}

	// Initialize and set policy engine
	policyEngine := policy.NewPolicyEngine()
	// Add default policies (already added in NewPolicyEngine)
	executor.SetPolicyEngine(policyEngine)

	opts := exec.ExecuteOptions{
		Command:    command,
		WorkingDir: workingDir,
		Reversible: execReversible,
		BackupType: backupType,
		IntentID:   execIntent,
		AgentID:    execAgent,
		DryRun:     execDryRun,
	}

	result := executor.Execute(opts)

	if execDryRun {
		fmt.Printf("[DRY RUN] Would execute: %s\n", command)
		if execReversible {
			fmt.Printf("[DRY RUN] Backup type: %s\n", backupType)
		}
		if execIntent != "" {
			fmt.Printf("[DRY RUN] Linked to intent: %s\n", execIntent)
		}
		if !result.Success && result.Error != nil {
			fmt.Printf("[DRY RUN] Error: %v\n", result.Error)
		}
		return nil
	}

	actionID := generateActionID(command)

	if result.Success {
		fmt.Printf("✓ Executed: %s\n", command)
		fmt.Printf("  Action ID: %s\n", actionID)
		if result.BackupPath != "" {
			fmt.Printf("  Backup:    %s\n", result.BackupPath)
		}
		if execIntent != "" {
			fmt.Printf("  Intent:    %s\n", execIntent)
		}
	} else {
		fmt.Printf("✗ Failed: %s\n", command)
		if result.Error != nil {
			fmt.Printf("  Error: %v\n", result.Error)
		}
		if result.BackupPath != "" {
			fmt.Printf("  Backup: %s (automatic restore attempted)\n", result.BackupPath)
		}
	}

	db, err := storage.NewDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	status := exec.StatusExecuted
	if !result.Success {
		status = exec.StatusFailed
	}

	_, err = db.Exec(
		`INSERT INTO reversible_actions (id, attestation_id, command, working_dir, backup_path, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		actionID, "", command, workingDir, result.BackupPath, status, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("failed to save action: %w", err)
	}

	if execIntent != "" {
		if _, err := db.Exec(`UPDATE reversible_actions SET attestation_id = ? WHERE id = ?`, execIntent, actionID); err != nil {
			fmt.Printf("Warning: failed to link intent to action: %v\n", err)
		}
	}

	return nil
}

func runExecRollback(id string) error {
	db, err := storage.NewDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if id == "last" {
		var lastID string
		err = db.QueryRow(
			`SELECT id FROM reversible_actions WHERE status = ? ORDER BY created_at DESC LIMIT 1`,
			exec.StatusExecuted,
		).Scan(&lastID)
		if err != nil {
			return fmt.Errorf("no pending rollbacks found")
		}
		id = lastID
	}

	var command, backupPath, originalPath string
	var status exec.ReversibleStatus
	err = db.QueryRow(
		`SELECT command, backup_path, working_dir, status FROM reversible_actions WHERE id = ?`,
		id,
	).Scan(&command, &backupPath, &originalPath, &status)

	if err != nil {
		return fmt.Errorf("action not found: %s", id)
	}

	if status == exec.StatusRolledBack {
		return fmt.Errorf("action already rolled back: %s", id)
	}

	executor, err := exec.NewExecutor(cfg.BackupDir)
	if err != nil {
		return err
	}

	if backupPath != "" && originalPath != "" {
		if err := executor.Rollback(id, backupPath, originalPath); err != nil {
			return fmt.Errorf("rollback failed: %w", err)
		}
	}

	if _, err := db.Exec(
		`UPDATE reversible_actions SET status = ?, rolled_back_at = ? WHERE id = ?`,
		exec.StatusRolledBack, time.Now().UTC().Format(time.RFC3339), id,
	); err != nil {
		fmt.Printf("Warning: failed to update action status in database: %v\n", err)
	}

	fmt.Printf("✓ Rolled back: %s\n", command)
	fmt.Printf("  Action ID: %s\n", id)
	return nil
}

func runExecHistory() error {
	db, err := storage.NewDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	limit := 50

	query := `SELECT id, backup_path, status, created_at, rolled_back_at FROM reversible_actions ORDER BY created_at DESC LIMIT ?`
	rows, err := db.Query(query, limit)
	if err != nil {
		return fmt.Errorf("failed to query history: %w", err)
	}
	defer rows.Close()

	type actionRow struct {
		ID           string
		BackupPath   string
		Status       exec.ReversibleStatus
		CreatedAt    string
		RolledBackAt *string
	}

	var actions []actionRow
	for rows.Next() {
		var r actionRow
		var rolledBack *string
		if err := rows.Scan(&r.ID, &r.BackupPath, &r.Status, &r.CreatedAt, &rolledBack); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}
		r.RolledBackAt = rolledBack
		actions = append(actions, r)
	}

	fmt.Printf("%-20s %-8s %-15s %s\n", "ID", "STATUS", "BACKUP", "CREATED")
	fmt.Printf("%-20s %-8s %-15s %s\n", "----", "------", "------", "-------")
	for _, a := range actions {
		statusIcon := "○"
		if a.Status == exec.StatusExecuted {
			statusIcon = "✓"
		} else if a.Status == exec.StatusRolledBack {
			statusIcon = "↩"
		} else if a.Status == exec.StatusFailed {
			statusIcon = "✗"
		}

		backup := "none"
		if a.BackupPath != "" {
			backup = filepath.Base(a.BackupPath)
		}

		rollback := ""
		if a.RolledBackAt != nil {
			rollback = " [rolled back]"
		}

		fmt.Printf("%-20s %s %-15s %s%s\n", a.ID[:20], statusIcon, backup, a.CreatedAt[:10], rollback)
	}

	return nil
}

func generateActionID(command string) string {
	data := fmt.Sprintf("exec:%s:%s", command, time.Now().UTC().Format(time.RFC3339))
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("exec:%x", hash[:8])
}

// containsDangerousPatterns and confirmDangerous are now handled by the guardrails package
