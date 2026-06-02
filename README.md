# Ransomware Early Warning and Recovery System

This is a behavior-based ransomware detection and recovery system utilizing a cloud-ready Agent-Server architecture.

## Structure
- `/agent`: The endpoint agent that monitors files locally, calculates entropy, and triggers backups.
- `/server`: The central Flask server that receives telemetry, logs events, and provides the dashboard.
- `/docs`: Documentation and architecture plans.
