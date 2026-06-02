# Ransomware Early Warning and Recovery System

This is a behavior-based ransomware detection and recovery system utilizing a cloud-ready Agent-Server architecture.

## Structure
- `/agent`: The endpoint agent that monitors files locally, calculates entropy, and triggers backups.
- `/server`: The central Flask server that receives telemetry, logs events, and provides the dashboard.
- `/docs`: Documentation and architecture plans.

## Team Member Setup & Testing Guide

If you have just cloned this repository, follow these steps to run and test the ransomware detection system on your local machine.

### 1. Prerequisites
You need **Python 3.8+** installed. Make sure to install the dependencies for both the agent and the server:
```bash
# Install Server dependencies
pip install -r server/requirements.txt

# Install Agent dependencies
pip install -r agent/requirements.txt
```

### 2. Environment Variables Configuration
Because `.env` files contain sensitive keys, they are not stored in GitHub. You must create them using the provided example files:
1. In the `server` folder, copy `.env.example` and rename it to `.env`.
2. In the `agent` folder, copy `.env.example` and rename it to `.env`.

### 3. Start the Server (Terminal 1)
The server acts as the centralized Security Operations Center (SOC) dashboard. It must be running to receive alerts.
```bash
cd server
python app.py
```
*You can now view the dashboard at `http://127.0.0.1:5000`*

### 3. Start the Agent (Terminal 2)
The agent silently monitors your file system.
```bash
cd agent
python main.py
```
*(It will create a `test_env` folder on your Desktop by default and monitor it for ransomware-like behavior).*

### 4. Simulate an Attack (Terminal 3)
To see the system in action, run the test script. It will generate dummy files and rapidly modify/encrypt them to trick the agent.
```bash
python test_agent.py
```
*Once the script finishes, check your browser dashboard (`http://127.0.0.1:5000`)! You will see the new Threat Alerts populate automatically without refreshing the page.*

## Cloud Deployment (Heroku/Render)

The server component is built to be easily deployed to a cloud platform:
1. Ensure your cloud provider sets the `DATABASE_URL` to a valid PostgreSQL connection string.
2. Ensure you define `SECRET_KEY` and `API_KEY` in the cloud environment settings.
3. The included `Procfile` uses `gunicorn` to run the Flask application in production mode.
