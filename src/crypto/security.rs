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
        
        report.push_str(&format!("📊 Statistik:\n"));
        report.push_str(&format!("   Gesamt Events: {}\n", total_events));
        report.push_str(&format!("   Fehlgeschlagene Logins: {}\n", auth_failures));
        report.push_str(&format!("   Verdächtige Aktivitäten: {}\n", suspicious_activities));
        
        if let Some(last) = self.last_success {
            let days_ago = (current_timestamp() - last) / (24 * 60 * 60);
            report.push_str(&format!("   Letzter erfolgreicher Login: vor {} Tagen\n", days_ago));
        }
        
        report.push_str("\n");
        
        // Aktuelle Warnungen
        if !self.failed_attempts.is_empty() {
            report.push_str("⚠️  AKTUELLE WARNUNGEN:\n");
            for (source, attempts) in &self.failed_attempts {
                if *attempts >= 3 {
                    report.push_str(&format!("   {} Fehlversuche von {}\n", attempts, source));
                }
            }
            report.push_str("\n");
        }
        
        // Empfehlungen
        report.push_str("💡 EMPFEHLUNGEN:\n");
        if auth_failures > 0 {
            report.push_str("   • Multi-Faktor-Authentifizierung aktivieren\n");
            report.push_str("   • Stärkeres Master-Passwort verwenden\n");
        }
        if suspicious_activities > 0 {
            report.push_str("   • Logs regelmäßig überprüfen\n");
            report.push_str("   • Backup-Wiederherstellung testen\n");
        }
        report.push_str("   • Regelmäßige Passwort-Rotation\n");
        report.push_str("   • Software-Updates installieren\n");
        
        report
    }
}

/// Incident Response Template
pub struct IncidentResponse;

impl IncidentResponse {
    /// Generiert E-Mail-Template für Sicherheitsvorfall
    pub fn generate_incident_email(incident_type: &str, details: &str) -> String {
        format!("Betreff: 🚨 SICHERHEITSVORFALL - Sofortige Maßnahmen erforderlich\n\n\
Liebe/r Nutzer/in,\n\n\
wir haben einen Sicherheitsvorfall in Ihrem PQC-Passwort-Manager entdeckt:\n\n\
VORFALL: {}\n\
DETAILS: {}\n\
ZEITPUNKT: {}\n\n\
SOFORTIGE MASSNAHMEN:\n\
1. ✅ Master-Passwort SOFORT ändern\n\
2. ✅ Alle gespeicherten Passwörter überprüfen und bei Verdacht ändern\n\
3. ✅ Verdächtige Login-Aktivitäten in anderen Accounts prüfen\n\
4. ✅ Backup erstellen (falls nicht vorhanden)\n\n\
EMPFOHLENE LANGFRISTIGE MASSNAHMEN:\n\
• Multi-Faktor-Authentifizierung für alle wichtigen Accounts\n\
• Regelmäßige Passwort-Rotation (alle 90 Tage)\n\
• Verwendung eines Hardware-Security-Keys\n\
• Regelmäßige Sicherheitsupdates\n\n\
Bei Fragen oder Verdacht auf Kompromittierung wenden Sie sich an:\n\
support@pqc-password-manager.com\n\n\
Mit freundlichen Grüßen,\n\
Das Sicherheitsteam\n\n\
---\n\
Diese Nachricht wurde automatisch generiert.",
            incident_type, details, format_timestamp(current_timestamp()))
    }
    
    /// Checkliste für Incident Response
    pub fn print_incident_checklist() {
        println!("🚨 INCIDENT RESPONSE CHECKLISTE");
        println!("================================");
        println!("□ 1. Vorfall dokumentieren und klassifizieren");
        println!("□ 2. Betroffene Systeme isolieren");
        println!("□ 3. Forensische Kopien erstellen");
        println!("□ 4. Nutzer benachrichtigen");
        println!("□ 5. Schwachstelle identifizieren und schließen");
        println!("□ 6. Systeme wiederherstellen");
        println!("□ 7. Monitoring verstärken");
        println!("□ 8. Post-Incident-Review durchführen");
        println!("□ 9. Dokumentation aktualisieren");
        println!("□ 10. Präventive Maßnahmen implementieren");
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
    format!("{:?}", datetime) // Vereinfacht - in Produktion bessere Formatierung
}

