Security Anomaly Detector

Detects anomalous login IPs from transactional data and writes alerts to a security table.
The detector combines an Isolation Forest model with a rule fallback (e.g., too many failed logins in a short window) to reduce blind spots and keep operations simple.

Typical use: run it on a schedule (cron/systemd/Task Scheduler) to scan recent login_attempts and insert normalized alerts into security_alerts.

✨ Key Features

Hybrid detection: Isolation Forest + configurable rule threshold (e.g., >= 5 failed logins / 15 min window).

Database-first workflow: reads from login_attempts, writes to security_alerts.

Idempotent inserts: avoids duplicate alerts for the same IP/time window.

Explainable outputs: each alert stores score, rule_triggered, timestamps, and notes.

Ops-friendly: CLI flags, .env config, structured logging.

🧱 Minimal Schema (example for MySQL)
-- Source table (simplified)
CREATE TABLE IF NOT EXISTS login_attempts (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(128),
  ip_address VARBINARY(16),       -- or VARCHAR(45) if you prefer
  user_agent TEXT,
  ts DATETIME NOT NULL,           -- timestamp
  success TINYINT(1) NOT NULL,    -- 1=ok, 0=failed
  INDEX (ts),
  INDEX (success),
  INDEX (ip_address)
);

-- Alerts sink
CREATE TABLE IF NOT EXISTS security_alerts (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  ip VARCHAR(45) NOT NULL,
  score DOUBLE,
  rule_triggered VARCHAR(64),     -- e.g., 'excessive_failures' / 'iforest'
  first_seen DATETIME,
  last_seen DATETIME,
  status ENUM('open','reviewed','closed') DEFAULT 'open',
  notes TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_ip_window (ip, first_seen, last_seen)
);


IPv4/IPv6: usa VARBINARY(16) si almacenas direcciones normalizadas; el script puede convertir a texto para reportes.

⚙️ Requirements

Python 3.10+

Packages:

pandas

scikit-learn

SQLAlchemy

PyMySQL (o el driver de tu motor: psycopg2, cx_Oracle, etc.)

python-dotenv

loguru (opcional para logs bonitos)

Install:

pip install -U pandas scikit-learn SQLAlchemy PyMySQL python-dotenv loguru

🔐 Configuration (.env)

Create a .env file in the project root:

# DB connection (examples)
DB_URL=mysql+pymysql://user:password@host:3306/your_db?charset=utf8mb4
# DB_URL=postgresql+psycopg2://user:password@host/db
# DB_URL=oracle+cx_oracle://user:password@host:1521/service

# Detection window (ISO-8601 or relative)
SINCE=2025-01-01T00:00:00
UNTIL=now

# Isolation Forest
IFOREST_CONTAMINATION=0.01
IFOREST_TREES=200
IFOREST_RANDOM_STATE=42

# Rule fallback
RULE_MAX_FAILED=5
RULE_WINDOW_MINUTES=15

# Table names (override if needed)
TABLE_LOGIN_ATTEMPTS=login_attempts
TABLE_ALERTS=security_alerts

# Logging
LOG_LEVEL=INFO

🚀 Quick Start
# 1) Clone your repo
git clone https://github.com/<your-user>/security-anomaly-detector.git
cd security-anomaly-detector

# 2) Create .env (see above) and install requirements
pip install -U pandas scikit-learn SQLAlchemy PyMySQL python-dotenv loguru

# 3) Run (dry-run first)
python ia_detector.py --dry-run

# 4) Persist alerts
python ia_detector.py


Common CLI flags (suggested):

--since '2025-09-01'     # override .env
--until 'now'            # default
--threshold -0.20        # Isolation Forest decision threshold (lower = more anomalies)
--dry-run                # don't insert alerts, just print summary
--verbose                # debug logs

🧠 How it Works

Extract: loads recent rows from login_attempts in the configured time window.

Feature build: aggregates by ip (fail ratio, attempts per minute, unique users, time-of-day, etc.).

Model: runs Isolation Forest → flags outliers (score < threshold).

Rule fallback: if an IP exceeds RULE_MAX_FAILED within RULE_WINDOW_MINUTES, raise an alert even if the model is uncertain.

Persist: inserts into security_alerts (idempotent key prevents duplicates).

Log & exit: prints counts and basic metrics for observability.

🧪 Example Alert (JSON)
{
  "ip": "203.0.113.24",
  "score": -0.37,
  "rule_triggered": "iforest",
  "first_seen": "2025-09-26T07:00:00",
  "last_seen": "2025-09-26T07:15:00",
  "notes": "high fail_ratio=0.92; attempts=31; unique_users=5",
  "status": "open"
}

🛠️ Scheduling

Linux (cron):

*/15 * * * * /usr/bin/python3 /opt/security-anomaly-detector/ia_detector.py >> /var/log/ia_detector.log 2>&1


Windows (Task Scheduler): create a task to run:

python C:\path\security-anomaly-detector\ia_detector.py

🔒 Security & Privacy

No secrets in code. Use .env or your OS secret manager.

Consider hashing/pseudonymizing username/user_agent if exporting outside the org.

Log at INFO by default; avoid writing full PII to logs.

📚 For Recruiters & Reviewers

Problem: detect suspicious access patterns early, without heavyweight SIEM rules.

Solution: light Python worker; hybrid detection to balance recall/precision.

Why it matters: reduces manual triage effort and surfaces high-risk IPs quickly.

OS angle: designed as a resource-light batch job (I/O bound, cron/systemd integration, predictable CPU/memory footprint).

🗺️ Roadmap

 Export alerts to webhook (Slack/Teams).

 Per-tenant baselines & time-of-day seasonality.

 Unit tests + synthetic data generator.

 Dockerfile and compose for quick spins.

🤝 Contributing

PRs and issues are welcome. Please include a short description, steps to reproduce, and proposed changes.

📄 License

MIT © 2025 Maicolm Rivera Zamudio

<details> <summary><strong>Versión en Español</strong></summary>

Security Anomaly Detector detecta IPs anómalas de inicio de sesión desde una base transaccional y registra alertas en security_alerts. Usa Isolation Forest más una regla de respaldo (muchos intentos fallidos en pocos minutos). Está pensado para correrse de forma programada (cron/Task Scheduler) con bajo consumo de recursos.

Características: pipeline híbrido, tablas claras (login_attempts → security_alerts), inserciones idempotentes, configuraciones por .env, logs estructurados.

Esquema mínimo: ver SQL arriba (MySQL).
Requisitos: Python 3.10+, pandas, scikit-learn, SQLAlchemy, driver de tu motor, python-dotenv.
Ejecución: configurar .env, probar con --dry-run, luego ejecutar sin él.
Seguridad: no expongas secretos, evita PII en logs.

</details>
Badges & About (sidebar suggestion for GitHub)

About: “Detection of anomalous login IPs using Isolation Forest + rule fallback. Inserts normalized alerts into security_alerts. Python 3.10+.”

Topics: security, anomaly-detection, isolation-forest, python, ops, login, authentication
