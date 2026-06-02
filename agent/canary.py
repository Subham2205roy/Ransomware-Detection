import os
import ctypes
import logging

class CanaryManager:
    def __init__(self, watch_directory):
        self.watch_directory = watch_directory
        # A mix of invisible temp-like files and tempting files
        self.canary_files = [
            "~$finance_passwords.xlsx",
            "~secret_backup.dat",
            "~$important_keys.txt"
        ]
        self.deployed_canaries = []

    def deploy_canaries(self):
        """Creates hidden honeypot files in the watch directory."""
        for filename in self.canary_files:
            file_path = os.path.join(self.watch_directory, filename)
            if os.path.exists(file_path):
                self.deployed_canaries.append(file_path)
                logging.info(f"Canary file already exists: {filename}")
                continue
                
            try:
                with open(file_path, "w") as f:
                    f.write("CONFIDENTIAL DATA\nDo not modify.")
                
                # Windows API to set file as hidden (FILE_ATTRIBUTE_HIDDEN = 0x02)
                success = ctypes.windll.kernel32.SetFileAttributesW(file_path, 2)
                if success:
                    self.deployed_canaries.append(file_path)
                    logging.info(f"Canary file deployed and hidden: {filename}")
                else:
                    logging.warning(f"Deployed canary {filename} but failed to hide it.")
            except Exception as e:
                logging.error(f"Failed to deploy canary {file_path}: {e}")

    def is_canary(self, file_path):
        """Checks if a given file path is a canary file."""
        return any(file_path.endswith(canary) for canary in self.canary_files)
