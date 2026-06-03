import os
import uuid
import socket
import logging
import requests
from dotenv import load_dotenv

load_dotenv()

SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:5000")
API_KEY = os.getenv("API_KEY", "test-api-key")

class APIClient:
    def __init__(self):
        self.server_url = SERVER_URL.rstrip('/')
        self.headers = {
            "X-API-Key": API_KEY,
            "Content-Type": "application/json"
        }
        self.agent_id = self._get_or_create_agent_id()
        self.hostname = socket.gethostname()
        
    def _get_or_create_agent_id(self):
        id_file = "agent_id.txt"
        if os.path.exists(id_file):
            with open(id_file, "r") as f:
                return f.read().strip()
        else:
            new_id = str(uuid.uuid4())
            with open(id_file, "w") as f:
                f.write(new_id)
            return new_id
            
    def register(self):
        """Registers the agent with the central server."""
        try:
            url = f"{self.server_url}/api/register"
            payload = {
                "agent_id": self.agent_id,
                "hostname": self.hostname
            }
            response = requests.post(url, json=payload, headers=self.headers, timeout=5)
            if response.status_code == 200:
                logging.info(f"Successfully registered agent with central server: {self.agent_id}")
                return True
            else:
                logging.warning(f"Failed to register agent. Server responded with Status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Connection error during server registration: {e}")
            return False

    def heartbeat(self):
        """Sends a periodic heartbeat to the server."""
        try:
            url = f"{self.server_url}/api/heartbeat"
            payload = {
                "agent_id": self.agent_id
            }
            requests.post(url, json=payload, headers=self.headers, timeout=5)
        except requests.exceptions.RequestException:
            # Silently fail on heartbeats to avoid log spamming if server goes down temporarily
            pass

    def send_alert(self, alert_type, severity, description, file_path=None, entropy=None):
        """Sends a threat alert to the central server."""
        try:
            url = f"{self.server_url}/api/alert"
            payload = {
                "agent_id": self.agent_id,
                "alert_type": alert_type,
                "severity": severity,
                "description": description
            }
            
            if file_path:
                payload["file_path"] = file_path
            if entropy:
                payload["entropy"] = entropy
                
            response = requests.post(url, json=payload, headers=self.headers, timeout=5)
            if response.status_code == 201:
                logging.info(f"Successfully transmitted {alert_type} alert to central server.")
                return True
            else:
                logging.error(f"Server rejected alert. Status: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Connection error transmitting alert to server: {e}")
            return False

    def poll_commands(self, folder_locked=False):
        """Polls the server for pending commands."""
        try:
            url = f"{self.server_url}/api/commands"
            payload = {
                "agent_id": self.agent_id,
                "folder_locked": folder_locked
            }
            response = requests.post(url, json=payload, headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get("commands", []), data.get("watch_directory")
            return [], None
        except requests.exceptions.RequestException:
            return [], None
