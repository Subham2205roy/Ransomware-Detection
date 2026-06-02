import os
import shutil
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

RECOVERY_DIR = os.getenv("RECOVERY_DIRECTORY", r"C:\.ransom_recovery_vault")

class RecoveryVault:
    def __init__(self):
        self.recovery_dir = RECOVERY_DIR
        self._ensure_vault_exists()
        
    def _ensure_vault_exists(self):
        """Creates the recovery directory if it doesn't exist and attempts to hide it."""
        try:
            if not os.path.exists(self.recovery_dir):
                os.makedirs(self.recovery_dir, exist_ok=True)
                logging.info(f"Recovery vault created at: {self.recovery_dir}")
                
                # Attempt to make directory hidden and system level on Windows
                if os.name == 'nt':
                    import ctypes
                    try:
                        # FILE_ATTRIBUTE_HIDDEN = 0x02, FILE_ATTRIBUTE_SYSTEM = 0x04
                        ctypes.windll.kernel32.SetFileAttributesW(self.recovery_dir, 0x02 | 0x04)
                        logging.info("Recovery vault successfully hidden from normal view.")
                    except Exception as e:
                        logging.warning(f"Could not hide recovery vault: {e}")
        except Exception as e:
            logging.error(f"Failed to create recovery vault: {e}")
            
    def backup_file(self, file_path):
        """Copies the specified file to the recovery vault securely."""
        if not os.path.exists(file_path):
            logging.warning(f"Cannot backup, file no longer exists: {file_path}")
            return None
            
        try:
            # Create a unique filename using timestamp to prevent collisions
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            basename = os.path.basename(file_path)
            safe_name = f"{timestamp}_{basename}"
            
            dest_path = os.path.join(self.recovery_dir, safe_name)
            
            # Copy file (using copy2 to preserve metadata)
            shutil.copy2(file_path, dest_path)
            logging.info(f"SECURE BACKUP SUCCESSFUL: {basename} saved to vault.")
            return dest_path
            
        except PermissionError:
            logging.error(f"Permission denied: Could not backup {file_path}. (File may be locked by ransomware)")
            return None
        except Exception as e:
            logging.error(f"Error during backup of {file_path}: {e}")
            return None
