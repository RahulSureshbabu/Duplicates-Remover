import os
import hashlib
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_file_hash_md5(file_path):
    """Compute MD5 hash of a file."""
    try:
        md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                md5.update(block)
        return md5.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def find_duplicates(folder_path, progress_var, progress_bar, update_display_callback, start_from_file=None):
    """Find duplicate files in a folder and its subfolders, keeping only the oldest file."""
    if not os.path.exists(folder_path):
        logging.error(f"Folder not found: {folder_path}")
        return [], [], None

    try:
        # Store all files to process for resuming capability
        if start_from_file is None:
            all_files = []
            for root, _, files in os.walk(folder_path):
                for file in files:
                    all_files.append(Path(root) / file)
        else:
            all_files = start_from_file

        file_hashes = {}
        duplicates = []
        originals = []
        processed_files = 0
        total_files = len(all_files)

        with ThreadPoolExecutor() as executor:
            for full_path in all_files:
                if update_display_callback and not update_display_callback(str(full_path)):
                    # Return current state if paused
                    remaining_files = all_files[processed_files:]
                    return duplicates, originals, remaining_files

                try:
                    file_hash = get_file_hash_md5(full_path)
                    if not file_hash:
                        continue

                    file_modified_date = full_path.stat().st_mtime
                    
                    if file_hash in file_hashes:
                        stored_file = file_hashes[file_hash]
                        if file_modified_date > stored_file['date']:
                            duplicates.append((full_path, file_modified_date))
                        else:
                            duplicates.append((stored_file['path'], stored_file['date']))
                            file_hashes[file_hash] = {'path': full_path, 'date': file_modified_date}
                            if (stored_file['path'], stored_file['date']) in originals:
                                originals.remove((stored_file['path'], stored_file['date']))
                            originals.append((full_path, file_modified_date))
                    else:
                        file_hashes[file_hash] = {'path': full_path, 'date': file_modified_date}
                        originals.append((full_path, file_modified_date))
                except Exception as e:
                    logging.error(f"Error processing file {full_path}: {str(e)}")
                    continue

                processed_files += 1
                progress_var.set((processed_files / total_files) * 100)
                progress_bar.update()

    except Exception as e:
        logging.error(f"Error in find_duplicates: {str(e)}")
        return [], [], None

    return duplicates, originals, None

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
