import os
import hashlib
from pathlib import Path

def get_file_hash_sha256(file_path):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(4096), b''):
            sha256.update(block)
    return sha256.hexdigest()

def find_duplicates(folder_path, progress_var, progress_bar):
    """Find duplicate files in a folder and its subfolders, keeping only the oldest file."""
    if not os.path.exists(folder_path):
        print(f"Folder not found: {folder_path}")
        return [], []

    file_hashes = {}
    duplicates = []
    originals = []
    total_files = sum([len(files) for _, _, files in os.walk(folder_path)])
    processed_files = 0

    for root, _, files in os.walk(folder_path):
        for file in files:
            full_path = Path(root) / file
            file_hash = get_file_hash_sha256(full_path)
            file_modified_date = full_path.stat().st_mtime

            if file_hash in file_hashes:
                stored_file = file_hashes[file_hash]
                if file_modified_date > stored_file['date']:
                    duplicates.append((full_path, file_modified_date))
                else:
                    duplicates.append((stored_file['path'], stored_file['date']))
                    file_hashes[file_hash] = {'path': full_path, 'date': file_modified_date}
            else:
                file_hashes[file_hash] = {'path': full_path, 'date': file_modified_date}
                originals.append((full_path, file_modified_date))

            processed_files += 1
            progress_var.set((processed_files / total_files) * 100)
            progress_bar.update()

    return duplicates, originals

def delete_files(files, progress_var, progress_bar):
    """Delete the specified files."""
    total_files = len(files)
    for i, file in enumerate(files):
        os.remove(file)
        progress_var.set(((i + 1) / total_files) * 100)
        progress_bar.update()

def calculate_total_size(files):
    """Calculate the total size of the specified files."""
    total_size = sum(file.stat().st_size for file in files)
    return total_size

LAST_PATH_FILE = "last_path.txt"

def save_last_path(path):
    """Save the last opened path to a file."""
    with open(LAST_PATH_FILE, "w") as f:
        f.write(path)

def load_last_path():
    """Load the last opened path from a file."""
    if os.path.exists(LAST_PATH_FILE):
        with open(LAST_PATH_FILE, "r") as f:
            return f.read().strip()
    return ""
