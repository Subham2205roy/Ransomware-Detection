import os
import subprocess
import time
import random

def run_test():
    watch_dir = r"C:\Users\HP\OneDrive\Desktop\TestFolder"
    os.makedirs(watch_dir, exist_ok=True)
    
    print("Starting agent in background...")
    # Start agent from the agent directory
    agent_proc = subprocess.Popen(
        ['python', 'main.py'], 
        cwd=r"C:\Users\HP\OneDrive\Desktop\Ransomware\agent",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for agent to initialize
    time.sleep(2)
    
    print("1. Simulating rapid file modifications (Behavior Alert test)...")
    for i in range(6):
        with open(os.path.join(watch_dir, f"test_file_{i}.txt"), "w") as f:
            f.write(f"This is a normal file {i}")
        time.sleep(0.1) # Rapidly create files
        
    time.sleep(1)
        
    print("2. Simulating high entropy file encryption (Entropy Alert test)...")
    # Generate high entropy data (random bytes)
    random_bytes = os.urandom(1024 * 50) # 50KB of pure random data
    with open(os.path.join(watch_dir, "encrypted_sim.dat"), "wb") as f:
        f.write(random_bytes)
        
    # Give agent time to process and log
    time.sleep(5)
    
    print("Stopping agent...")
    agent_proc.terminate()
    
    # Read output
    stdout, stderr = agent_proc.communicate()
    
    print("\n========== AGENT LOGS ==========")
    print(stderr) # logging uses stderr by default
    print("================================")
    
    print("Test Complete.")

if __name__ == "__main__":
    run_test()
