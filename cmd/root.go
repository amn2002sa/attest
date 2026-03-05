package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	DBPath    string
	DataDir   string
	BackupDir string
	Verbose   bool
	LogLevel  string
}

var (
	cfg        *Config
	dataDir    string
	configFile string
	verbose    bool
	jsonOutput bool
)

func initConfig() {
	v := setupViper()

	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dataDir = v.GetString("data_dir")
	if dataDir == "" {
		dataDir = filepath.Join(home, ".attest")
	}
	dataDir = os.ExpandEnv(dataDir)

	cfg = &Config{
		DBPath:    filepath.Join(dataDir, "attest.db"),
		DataDir:   dataDir,
		BackupDir: filepath.Join(dataDir, "backups"),
		Verbose:   verbose,
	}
}

func setupViper() *viper.Viper {
	v := viper.New()

	v.SetDefault("data_dir", "$HOME/.attest")
	v.SetDefault("log_level", "info")

	v.SetEnvPrefix("ATTEST")
	v.AutomaticEnv()

	v.Set("ignore_missing_config", true)

	return v
}

var rootCmd = &cobra.Command{
	Use:   "attest",
	Short: "Attest - AI Agent Testing & Validation Tool",
	Long: `Attest provides comprehensive testing, validation, and monitoring for AI agents.

Complete documentation is available at https://github.com/provnai/attest`,
}

func Execute() error {
	initConfig()
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.attest.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output as JSON")

	// initCmd is added in cmd/init.go init()
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(attestCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(intentCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(queryCmd)
	rootCmd.AddCommand(gitCmd)
	rootCmd.AddCommand(identityCmd)
	rootCmd.AddCommand(hardwareCmd)
}
