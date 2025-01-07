import hashlib
import os

def calculate_file_hash(filepath):
    """Calculate the hash of a file using SHA-256."""
    hash_function = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hash_function.update(chunk)
    return hash_function.hexdigest()

def monitor_files(filepaths):
    """Monitor a list of files for changes by comparing hash values."""
    file_hashes = {filepath.strip('"'): calculate_file_hash(filepath.strip('"')) for filepath in filepaths}
    print("Initial file hashes calculated:")
    for filepath, file_hash in file_hashes.items():
        print(f"{filepath}: {file_hash}")
    
    try:
        while True:
            for filepath in filepaths:
                filepath = filepath.strip('"')
                if os.path.exists(filepath):
                    current_hash = calculate_file_hash(filepath)
                    if current_hash != file_hashes[filepath]:
                        print(f"File changed: {filepath}")
                        print(f"New hash: {current_hash}")
                        file_hashes[filepath] = current_hash
                else:
                    print(f"File not found: {filepath}")
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    files_to_monitor = input("Enter the paths of the files to monitor, separated by commas: ").split(",")
    files_to_monitor = [filepath.strip() for filepath in files_to_monitor]
    monitor_files(files_to_monitor)
