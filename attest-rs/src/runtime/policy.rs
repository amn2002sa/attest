use regex::Regex;
use serde::{Deserialize, Serialize};

/// Decisions the policy engine can make
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Block,
    Warn,
    Audit,
}

/// Importance of a policy violation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Defines the rules for a policy match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub command_regex: Option<String>,
    pub environment: Option<String>,
}

/// A security policy that governs agent behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub condition: PolicyCondition,
    pub action: PolicyAction,
    pub severity: PolicySeverity,
    pub enabled: bool,
}

/// The result of evaluating a command against a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub policy_id: String,
    pub matched: bool,
    pub action: PolicyAction,
    pub message: String,
}

impl Policy {
    /// Evaluate a single policy against a command
    pub fn evaluate(&self, cmd: &str) -> PolicyResult {
        if !self.enabled {
            return PolicyResult {
                policy_id: self.id.clone(),
                matched: false,
                action: PolicyAction::Allow,
                message: "Policy disabled".into(),
            };
        }

        // Check command regex
        if let Some(pattern) = &self.condition.command_regex {
            match Regex::new(pattern) {
                Ok(re) => {
                    if re.is_match(cmd) {
                        return PolicyResult {
                            policy_id: self.id.clone(),
                            matched: true,
                            action: self.action.clone(),
                            message: format!(
                                "Command matched policy '{}': {}",
                                self.name, self.description
                            ),
                        };
                    }
                }
                Err(e) => {
                    return PolicyResult {
                        policy_id: self.id.clone(),
                        matched: false,
                        action: PolicyAction::Audit,
                        message: format!("Invalid Regex in policy: {}", e),
                    };
                }
            }
        }

        PolicyResult {
            policy_id: self.id.clone(),
            matched: false,
            action: PolicyAction::Allow,
            message: "No match".into(),
        }
    }
}

/// Main engine for evaluating multiple policies
pub struct PolicyEngine {
    pub policies: Vec<Policy>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Add a policy to the engine
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }

    /// Check if a command should be allowed
    pub fn should_allow(&self, cmd: &str) -> (bool, Vec<PolicyResult>) {
        let mut results = Vec::new();
        let mut allow = true;

        for policy in &self.policies {
            let res = policy.evaluate(cmd);
            if res.matched {
                if res.action == PolicyAction::Block {
                    allow = false;
                }
                results.push(res);
            }
        }

        (allow, results)
    }

    /// Load default safety policies
    pub fn load_defaults(&mut self) {
        self.add_policy(Policy {
            id: "block-destructive-rm".into(),
            name: "Destructive RM Protection".into(),
            description: "Blocks dangerous recursive deletions".into(),
            condition: PolicyCondition {
                command_regex: Some(r"(?i)rm\s+-(rf|fr|r\s+-f|f\s+-r)".into()),
                environment: None,
            },
            action: PolicyAction::Block,
            severity: PolicySeverity::Critical,
            enabled: true,
        });

        self.add_policy(Policy {
            id: "warn-env-vars".into(),
            name: "Environment Variable Exposure".into(),
            description: "Warns about commands that print environment variables".into(),
            condition: PolicyCondition {
                command_regex: Some(r"(?i)(env|printenv|set)".into()),
                environment: None,
            },
            action: PolicyAction::Warn,
            severity: PolicySeverity::Medium,
            enabled: true,
        });

        self.add_policy(Policy {
            id: "block-network-discovery".into(),
            name: "Network Discovery Block".into(),
            description: "Prevents recon tools like nmap".into(),
            condition: PolicyCondition {
                command_regex: Some(r"(?i)nmap|netstat|ss\s+-".into()),
                environment: None,
            },
            action: PolicyAction::Block,
            severity: PolicySeverity::High,
            enabled: true,
        });
    }
}
