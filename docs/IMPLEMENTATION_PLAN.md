# Ransomware Early Warning and Recovery System (Cloud-Ready)

This implementation plan outlines the 16-phase development of a cloud-ready, agent-server ransomware detection system. It is permanently saved to your project directory.

## User Review Required

> [!IMPORTANT]
> Please review this updated, cloud-ready architecture plan. The tasks have been slightly modified to ensure that when you want to host the web dashboard in the future, it will be a seamless process.
> Do you approve this updated approach?

## Proposed Changes & Work Distribution (5 Members)

### Phase 1: Repository Setup & Cloud-Ready Architecture
*   **Goal:** Setup Git, Python environments, and establish the Agent-Server folder structure.
*   **Tasks:** Create `/agent` (Local Client) and `/server` (Cloud Dashboard) directories. Setup `.env` files for `SERVER_URL` and `DATABASE_URL`.

### Phase 2: Database Design with SQLAlchemy (Server)
*   **Team:** Member 5 (Dashboard, Database & Reporting)
*   **Tasks:** Implement SQLAlchemy models for `Agent`, `EventLog`, and `Alert`. Use SQLite for local development, but ensure PostgreSQL compatibility for future hosting.

### Phase 3: Core File Monitoring (Agent)
*   **Team:** Member 1 (File Monitoring)
*   **Tasks:** Implement `watchdog` to monitor target directories on the local machine and queue events in memory.

### Phase 4: Entropy Engine (Agent)
*   **Team:** Member 3 (Entropy & Threat Detection)
*   **Tasks:** Develop the Shannon entropy function to run efficiently against queued file modification events locally.

### Phase 5: Behavior Metric Tracking (Agent)
*   **Team:** Member 2 (Behavior Analysis)
*   **Tasks:** Build sliding-window logic to detect rapid modifications or mass file extension changes.

### Phase 6: Recovery Module & Local Vault (Agent)
*   **Team:** Member 4 (Recovery Module)
*   **Tasks:** Use `shutil` to safely back up files to a local hidden vault (e.g., `C:\.recovery_vault\`) when suspicious behavior is detected.

### Phase 7: Threat Detection Engine (Agent)
*   **Team:** Member 3 & Member 2
*   **Tasks:** Combine entropy and behavior scores. Determine thresholds that trigger a local recovery action and formulate an alert payload.

### Phase 8: RESTful API Development (Server)
*   **Team:** Member 5 & Member 1
*   **Tasks:** Build Flask endpoints (`/api/register`, `/api/alert`, `/api/heartbeat`) on the centralized server to receive telemetry from the Agent. Secure with API keys.

### Phase 9: Agent-to-Server Communication (Agent)
*   **Team:** All Members
*   **Tasks:** Integrate the `requests` library in the local Agent to push local alerts and health metrics securely to the Flask Server.

### Phase 10: Dashboard Scaffolding (Server)
*   **Team:** Member 5
*   **Tasks:** Create Bootstrap-based UI templates for the centralized web dashboard.

### Phase 11: Real-time Dashboard Updates (Server)
*   **Team:** Member 3 & Member 5
*   **Tasks:** Implement AJAX polling or WebSockets in the Flask app so the web dashboard updates instantly when an Agent sends a threat alert.

### Phase 12: PDF Reporting (Server)
*   **Team:** Member 5
*   **Tasks:** Use `reportlab` to generate downloadable incident reports dynamically from the server dashboard.

### Phase 13: End-to-End System Integration
*   **Team:** All Members
*   **Tasks:** Run the Agent on one machine (or terminal) and the Flask Server on another port. Verify end-to-end data flow (File Modify -> Detection -> Backup -> Cloud Alert).

### Phase 14: Threat Simulation & Testing
*   **Team:** Member 2 & Member 1
*   **Tasks:** Run mock ransomware scripts to verify the Agent detects the threat, creates local backups, and successfully alerts the server.

### Phase 15: Optimization for Hosting
*   **Team:** Member 3 & Member 2
*   **Tasks:** Add `gunicorn` configuration, generate strict `requirements.txt` files for both Agent and Server, and test database migration (SQLite to PostgreSQL).

### Phase 16: Final Packaging & Deployment Ready
*   **Team:** All Members
*   **Tasks:** Write `README.md`, setup instructions, architecture documentation, and create a `Procfile` for cloud deployment.
