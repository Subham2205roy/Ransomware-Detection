# Ransomware Early Warning and Recovery System

This is a behavior-based ransomware detection and recovery system utilizing a cloud-ready Agent-Server architecture.

## Structure
- `/agent`: The endpoint agent that monitors files locally, calculates entropy, and triggers backups.
- `/server`: The central Flask server that receives telemetry, logs events, and provides the dashboard.
- `/docs`: Documentation and architecture plans.

## Team Member Setup & Testing Guide

If you have just cloned this repository, follow these steps to run and test the ransomware detection system on your local machine.

### Step 1: Clone the Repository
Open a terminal and clone the repository. We will explicitly tell Git to name the folder `Ransomware` so it matches your local setup:
```bash
git clone https://github.com/Subham2205roy/Ransomware-Detection.git Ransomware
cd Ransomware
```

### Step 2: Set Up the Server (Terminal 1)
The central server handles the database and the SOC dashboard. It must be started first.
```bash
cd server
pip install -r requirements.txt

# Copy the example environment file
copy .env.example .env

# Run the server
python app.py
```
*You can now view the live SOC dashboard at `http://127.0.0.1:5000/dashboard`*

### Step 3: Start the Security Agent (Terminal 2)
Open a **new** terminal window, navigate back to the root `Ransomware` folder, and set up the agent.
```bash
cd agent
pip install -r requirements.txt

# Copy the example environment file
copy .env.example .env

# Run the agent
python main.py
```
*(The agent will silently run in the background, deploy honeypot canaries, and register with the SOC Dashboard).*

### Step 4: Simulate an Attack (Terminal 3)
To see the system in action, open a **third** terminal window in the root `Ransomware` folder and run the attack simulator:
```bash
python test_agent.py
```
*Once the script runs, check your browser dashboard! The agent will detect the anomaly, instantly lock down the folder to prevent encryption, and a forensic PDF report will be generated.*

## Cloud Deployment (Heroku/Render)

The server component is built to be easily deployed to a cloud platform:
1. Ensure your cloud provider sets the `DATABASE_URL` to a valid PostgreSQL connection string.
2. Ensure you define `SECRET_KEY` and `API_KEY` in the cloud environment settings.
3. The included `Procfile` uses `gunicorn` to run the Flask application in production mode.
