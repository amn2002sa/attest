package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/provnai/attest/pkg/policy"
)

var policyJSON bool

func init() {
	policyCmd.AddCommand(policyCheckCmd)
	policyCmd.AddCommand(policyAddCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyRemoveCmd)

	policyCmd.PersistentFlags().BoolVar(&policyJSON, "json", false, "output as JSON")
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage policies",
	Long:  `Configure and manage safety policies for agent actions.`,
}

var policyCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check action against policies",
	Long:  `Test if an action would be allowed or blocked by current policies.`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Policy check - provide action details:")
		fmt.Println("Usage: attest policy check --type command --target 'rm -rf'")
		fmt.Println("(Full implementation coming)")
	},
}

var policyAddCmd = &cobra.Command{
	Use:   "add [file]",
	Short: "Add a policy",
	Long:  `Add a policy from a YAML file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]
		p, err := policy.LoadPolicyFromFile(file)
		if err != nil {
			fmt.Printf("Error loading policy: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Policy loaded: %s (%s)\n", p.Name, p.ID)
		fmt.Printf("(Full add implementation coming)")
	},
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List policies",
	Long:  `List all active policies.`,
	Run: func(cmd *cobra.Command, args []string) {
		engine := policy.NewPolicyEngine()
		policies := engine.ListPolicies()

		if policyJSON {
			data, _ := json.MarshalIndent(policies, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("%-25s %-30s %-10s %-8s\n", "ID", "NAME", "ACTION", "ENABLED")
		fmt.Printf("%-25s %-30s %-10s %-8s\n", "-------------------------", "------------------------------", "----------", "--------")
		for _, p := range policies {
			enabled := "Yes"
			if !p.Enabled {
				enabled = "No"
			}
			name := p.Name
			if len(name) > 28 {
				name = name[:28] + ".."
			}
			id := p.ID
			if len(id) > 24 {
				id = id[:24]
			}
			fmt.Printf("%-25s %-30s %-10s %-8s\n", id, name, p.Action, enabled)
		}
		fmt.Printf("\nTotal: %d policies\n", len(policies))
	},
}

var policyRemoveCmd = &cobra.Command{
	Use:   "remove [id]",
	Short: "Remove a policy",
	Long:  `Remove a policy by ID.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Would remove policy: %s\n", args[0])
		fmt.Printf("(Full remove implementation coming)")
	},
}
