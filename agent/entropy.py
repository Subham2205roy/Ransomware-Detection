import math
import os
import logging

def calculate_shannon_entropy(file_path, chunk_size=8192):
    """
    Calculates the Shannon entropy of a file.
    High entropy (close to 8.0) suggests encryption or compression.
    """
    if not os.path.exists(file_path):
        return 0.0

    # We use a byte frequency array of size 256
    byte_counts = [0] * 256
    total_bytes = 0

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                for byte in chunk:
                    byte_counts[byte] += 1
                total_bytes += len(chunk)
                
        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
                
        return entropy

    except PermissionError:
        # Expected for system files or locked files
        pass
    except Exception as e:
        logging.debug(f"Error calculating entropy for {file_path}: {e}")
        
    return 0.0
