# Advanced Architecture Design: Ransomware Early Warning & Recovery System

## 1. System Overview (Cloud-Ready Agent-Server Architecture)
To ensure the system can be seamlessly hosted in the future without major rewrites, we must adopt a **Distributed Agent-Server Architecture**. 
Ransomware monitoring *must* happen locally on the victim's machine, but the dashboard, logging, and reporting should be centralized and hostable in the cloud.

### 1.1 High-Level Components
1. **Endpoint Agent (Local Client):** A lightweight Python background service running on the user's PC. It handles file monitoring, behavior/entropy analysis, and local recovery.
2. **Central Management Server (Cloud/Hosted):** A Flask-based web application that receives data from the Endpoint Agent, stores it in a database, and provides the UI dashboard.

---

## 2. Component Breakdown

### 2.1 The Endpoint Agent (Client-Side)
This component is installed on the machines being protected. It operates independently of the server's uptime to ensure constant protection.
*   **File Monitoring Module (`watchdog`):** Listens to OS-level file events (Create, Modify, Delete, Rename).
*   **Analysis Engine:**
    *   **Behavior Tracking:** Counts modification/deletion frequencies in memory (e.g., using a sliding window algorithm).
    *   **Entropy Calculator:** Calculates Shannon entropy of modified files to detect encryption.
*   **Local Recovery Module (`shutil`):** Immediately copies suspicious files to a secure, hidden, read-only local directory (`C:\.ransom_recovery_vault\`) before they are fully encrypted.
*   **Telemetry & API Client (`requests`):** Sends JSON payloads via HTTPS to the central Flask Server whenever an alert is triggered or a heartbeat is needed. Configured via a `.env` file containing the `SERVER_URL`.

### 2.2 The Central Management Server (Cloud-Hosted)
This component can be deployed to any cloud provider (e.g., Vercel, Render, Heroku, AWS).
*   **Flask REST API:** Endpoints to receive data (e.g., `POST /api/v1/alerts`, `POST /api/v1/heartbeat`).
*   **Database Abstraction (SQLAlchemy):** We will use SQLAlchemy ORM. This allows us to use **SQLite for local development**, but easily switch to **PostgreSQL** for cloud hosting by simply changing a single database connection string.
*   **Authentication (JWT / API Keys):** Ensures that only authorized Endpoint Agents can send data to the server.
*   **Web Dashboard (HTML/CSS/Bootstrap):** Displays real-time charts, active threats, and logs to system administrators.
*   **Reporting Module (`reportlab`):** Generates PDF reports of incidents on-demand from the web interface.

---

## 3. Data Flow & Execution Sequence

1. **Event Trigger:** A user's file is rapidly modified by a script.
2. **Local Processing:** The local Agent intercepts the event, calculates high entropy, and evaluates behavior rules.
3. **Threat Detection:** System detects an anomaly -> Triggers Local Recovery (back up the original file).
4. **Cloud Notification:** Agent formats an alert as JSON and sends an HTTP POST request to the Hosted Server.
5. **Storage:** The Server validates the API key, receives the alert, and stores it in the database.
6. **Admin Alert:** The Administrator viewing the cloud dashboard sees a real-time notification (via AJAX polling or WebSockets).

---

## 4. Hosting Considerations & Future-Proofing Requirements

To ensure **zero problems** during future cloud hosting, the development must follow these rules strictly:
*   **Environment Variables (`.env`):** Hardcoded URLs or Database paths are strictly prohibited. The server's address (`SERVER_URL`) and Database URI (`DATABASE_URL`) must be loaded from environment variables using `python-dotenv`.
*   **Stateless Server:** The Flask server will not store session data in local memory or local files. All state will be stored in the database.
*   **ORM Usage:** Direct SQLite SQL queries (like `SELECT * FROM table`) will be avoided. Using SQLAlchemy ensures the database engine is agnostic and interchangeable.
*   **Web Server Gateway Interface (WSGI):** The Flask app will be tested and built to run via `gunicorn`, which is standard for hosting environments, rather than just the built-in Flask development server.
*   **Storage Emancipation:** The Flask server shouldn't save things like generated PDFs locally. If generated, they should be served directly as binary streams or stored in cloud storage (like AWS S3) if persistence is needed.
