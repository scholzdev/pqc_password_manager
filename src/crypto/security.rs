/// Security monitoring and incident response
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    /// Failed authentication attempt
    AuthFailure {
        timestamp: u64,
        attempts: u32,
        source: String,
    },
    /// Suspicious activity detected
    SuspiciousActivity {
        timestamp: u64,
        event_type: String,
        details: String,
    },
    /// Successful authentication after failures
    AuthSuccess {
        timestamp: u64,
        previous_failures: u32,
    },
    /// Password rotation recommended
    PasswordRotationDue {
        timestamp: u64,
        service: String,
        last_changed: u64,
    },
}

pub struct SecurityMonitor {
    events: Vec<SecurityEvent>,
    failed_attempts: HashMap<String, u32>,
    last_success: Option<u64>,
}

impl Default for SecurityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityMonitor {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            failed_attempts: HashMap::new(),
            last_success: None,
        }
    }
    
    /// Records a failed authentication attempt
    pub fn record_auth_failure(&mut self, source: &str) {
        let timestamp = current_timestamp();
        let attempts = self.failed_attempts.entry(source.to_string()).or_insert(0);
        *attempts += 1;
        
        self.events.push(SecurityEvent::AuthFailure {
            timestamp,
            attempts: *attempts,
            source: source.to_string(),
        });
        
        // Warning for too many failed attempts
        if *attempts >= 5 {
            println!("🚨 SECURITY WARNING: {} failed attempts from {}", attempts, source);
            println!("   Consider account lockout or additional security measures!");
        }
    }
    
    /// Records a successful authentication
    pub fn record_auth_success(&mut self, source: &str) {
        let timestamp = current_timestamp();
        let previous_failures = self.failed_attempts.remove(source).unwrap_or(0);
        
        if previous_failures > 0 {
            self.events.push(SecurityEvent::AuthSuccess {
                timestamp,
                previous_failures,
            });
        }
        
        self.last_success = Some(timestamp);
    }
    
    /// Checks if password rotation is recommended
    pub fn check_password_rotation(&mut self, service: &str, last_changed: u64) {
        let timestamp = current_timestamp();
        const ROTATION_INTERVAL: u64 = 90 * 24 * 60 * 60; // 90 days in seconds
        
        if timestamp - last_changed > ROTATION_INTERVAL {
            self.events.push(SecurityEvent::PasswordRotationDue {
                timestamp,
                service: service.to_string(),
                last_changed,
            });
            
            println!("🔄 RECOMMENDATION: Password for '{}' is {} days old - rotation recommended!", 
                service, (timestamp - last_changed) / (24 * 60 * 60));
        }
    }
    
    /// Generates security report
    pub fn generate_security_report(&self) -> String {
        let mut report = String::new();
        report.push_str("🛡️  SECURITY REPORT\n");
        report.push_str("=================\n\n");
        
        // Statistics
        let total_events = self.events.len();
        let auth_failures = self.events.iter()
            .filter(|e| matches!(e, SecurityEvent::AuthFailure { .. }))
            .count();
        let suspicious_activities = self.events.iter()
            .filter(|e| matches!(e, SecurityEvent::SuspiciousActivity { .. }))
            .count();
        
        report.push_str(&"📊 Statistics:\n".to_string());
        report.push_str(&format!("   Total Events: {}\n", total_events));
        report.push_str(&format!("   Failed Logins: {}\n", auth_failures));
        report.push_str(&format!("   Suspicious Activities: {}\n", suspicious_activities));
        
        if let Some(last) = self.last_success {
            let days_ago = (current_timestamp() - last) / (24 * 60 * 60);
            report.push_str(&format!("   Last Successful Login: {} days ago\n", days_ago));
        }
        
        report.push('\n');
        
        // Current warnings
        if !self.failed_attempts.is_empty() {
            report.push_str("⚠️  CURRENT WARNINGS:\n");
            for (source, attempts) in &self.failed_attempts {
                if *attempts >= 3 {
                    report.push_str(&format!("   {} failed attempts from {}\n", attempts, source));
                }
            }
            report.push('\n');
        }
        
        // Recommendations
        report.push_str("💡 RECOMMENDATIONS:\n");
        if auth_failures > 0 {
            report.push_str("   • Enable Multi-Factor Authentication\n");
            report.push_str("   • Use stronger master password\n");
        }
        if suspicious_activities > 0 {
            report.push_str("   • Check logs regularly\n");
            report.push_str("   • Test backup recovery\n");
        }
        report.push_str("   • Regular password rotation\n");
        report.push_str("   • Install software updates\n");
        
        report
    }
}

/// Incident Response Template
pub struct IncidentResponse;

impl IncidentResponse {
    /// Generate email template for security incident
    pub fn generate_incident_email(incident_type: &str, details: &str) -> String {
        format!("Subject: 🚨 SECURITY INCIDENT - Immediate Action Required\n\n\
Dear User,\n\n\
We have detected a security incident in your PQC Password Manager:\n\n\
INCIDENT: {}\n\
DETAILS: {}\n\
TIMESTAMP: {}\n\n\
IMMEDIATE ACTIONS:\n\
1. ✅ Change master password IMMEDIATELY\n\
2. ✅ Review all stored passwords and change if suspicious\n\
3. ✅ Check for suspicious login activities in other accounts\n\
4. ✅ Create backup (if not already available)\n\n\
RECOMMENDED LONG-TERM MEASURES:\n\
• Multi-Factor Authentication for all important accounts\n\
• Regular password rotation (every 90 days)\n\
• Use of Hardware Security Key\n\
• Regular security updates\n\n\
For questions or suspected compromise, contact:\n\
support@pqc-password-manager.com\n\n\
Best regards,\n\
The Security Team\n\n\
---\n\
This message was automatically generated.",
            incident_type, details, format_timestamp(current_timestamp()))
    }
    
    /// Checklist for Incident Response
    pub fn print_incident_checklist() {
        println!("🚨 INCIDENT RESPONSE CHECKLIST");
        println!("===============================");
        println!("□ 1. Document and classify incident");
        println!("□ 2. Isolate affected systems");
        println!("□ 3. Create forensic copies");
        println!("□ 4. Notify users");
        println!("□ 5. Identify and close vulnerability");
        println!("□ 6. Restore systems");
        println!("□ 7. Strengthen monitoring");
        println!("□ 8. Conduct post-incident review");
        println!("□ 9. Update documentation");
        println!("□ 10. Implement preventive measures");
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
    format!("{:?}", datetime)
}

