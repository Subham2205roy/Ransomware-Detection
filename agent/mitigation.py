import os
import psutil
import logging
import stat
import subprocess

class ActiveMitigation:
    def __init__(self, watch_directory):
        self.watch_directory = watch_directory
        self.my_pid = os.getpid()

    def kill_suspect_process(self, file_path):
        """
        Attempts to find and terminate the process holding an open handle to file_path.
        Returns a list of terminated PIDs.
        """
        terminated_pids = []
        try:
            target_path = os.path.abspath(file_path).lower()
            current_user = psutil.Process().username()
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    # Skip our own process
                    if proc.info['pid'] == self.my_pid:
                        continue
                    
                    # Optimization: Only check processes running as the current user
                    # This prevents psutil.open_files() from hanging on SYSTEM processes
                    if proc.info.get('username') != current_user:
                        continue
                    
                    # open_files() may throw AccessDenied for elevated processes
                    for f in proc.open_files():
                        if f.path.lower() == target_path:
                            logging.warning(f"Process {proc.info['name']} (PID: {proc.info['pid']}) is touching {file_path}. Terminating!")
                            proc.kill()
                            terminated_pids.append(proc.info['pid'])
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                    
        except Exception as e:
            logging.error(f"Error during process mitigation: {e}")
            
        return terminated_pids

    def lockdown_directory(self):
        """
        Makes the watched directory and all files inside read-only using Windows icacls.
        This prevents ransomware from writing, modifying, or deleting files.
        """
        try:
            # (OI)(CI) = Object Inherit, Container Inherit (applies to all files and subfolders)
            # W,D = Write, Delete
            cmd = ['icacls', self.watch_directory, '/deny', 'Everyone:(OI)(CI)(W,D)']
            subprocess.run(cmd, capture_output=True, check=True, text=True)
            
            logging.info(f"Directory {self.watch_directory} locked down (Write/Delete Denied) successfully via icacls.")
            return True
        except Exception as e:
            logging.error(f"Failed to lockdown directory: {e}")
            return False

    def unlock_directory(self):
        """Restores write permissions to the directory."""
        try:
            # Remove the explicit deny rule for Everyone
            cmd = ['icacls', self.watch_directory, '/remove:d', 'Everyone', '/T']
            subprocess.run(cmd, capture_output=True, check=True, text=True)
            logging.info(f"Directory {self.watch_directory} unlocked (Write restored).")
        except Exception as e:
            logging.error(f"Failed to unlock directory: {e}")
