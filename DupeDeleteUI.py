import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar, Treeview, Style, Scrollbar  # Added Scrollbar import
from pathlib import Path
import os
import sys
import logging
import time
import csv
import threading
from functools import partial

# Ensure the current directory is in the Python path
sys.path.append(os.path.dirname(__file__))

from DupeDeleteLogic import (
    find_duplicates,
    delete_files,
    calculate_total_size,
    save_last_path,
    load_last_path,
    get_file_hash_md5  # Updated import
)

# Log the current working directory for debugging
logging.basicConfig(level=logging.INFO)
logging.info(f"Current working directory: {os.getcwd()}")

scanning = False
start_time = None
paused = False
pause_button = None
file_hash_cache = {}  # Cache for file hashes
file_pairs_cache = {}  # Cache for duplicate-original pairs
hash_to_originals = {}  # Maps hash to original file
hash_to_duplicates = {}  # Maps hash to duplicate files
remaining_files = None

def browse_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder_path)
        save_last_path(folder_path)
        start_scanning()  # Use start_scanning instead of direct call

def refresh_folder():
    start_scanning()  # Use start_scanning instead of direct call

def list_duplicates():
    global scanning, start_time, paused, file_hash_cache, file_pairs_cache, hash_to_originals, hash_to_duplicates, remaining_files
    if not folder_entry.get():
        messagebox.showwarning("Warning", "Please select a folder first")
        scanning = False
        scan_button.config(text="Scan")
        return

    if not scanning:
        return

    folder_path = folder_entry.get()
    if not paused:
        # Only clear caches and trees if not resuming from pause
        file_hash_cache.clear()
        file_pairs_cache.clear()
        hash_to_originals.clear()
        hash_to_duplicates.clear()
        duplicates_treeview.delete(*duplicates_treeview.get_children())
        originals_treeview.delete(*originals_treeview.get_children())

    progress_var.set(0)
    status_label.config(text=f"Searching in folder: {folder_path}")
    start_time = time.time()

    def update_display_callback(current_file):
        if not scanning:
            return False
        current_file_label.config(text=f"Processing: {current_file}")
        root.update_idletasks()
        return not paused  # Return True to continue, False to pause

    duplicates, originals, remaining = find_duplicates(
        folder_path, 
        progress_var, 
        progress_bar, 
        update_display_callback,
        remaining_files if paused else None
    )

    # Store remaining files for resume
    remaining_files = remaining

    # Display results and keep existing results if paused
    duplicate_paths = {str(path) for path, _ in duplicates}
    
    # Build hash maps during scan
    for file_path, _ in duplicates:
        try:
            file_hash = get_file_hash_md5(Path(file_path))
            if file_hash:
                if file_hash not in hash_to_duplicates:
                    hash_to_duplicates[file_hash] = []
                hash_to_duplicates[file_hash].append(str(file_path))
                file_hash_cache[str(file_path)] = file_hash
        except Exception:
            continue

    for file_path, _ in originals:
        try:
            file_hash = get_file_hash_md5(Path(file_path))
            if file_hash:
                hash_to_originals[file_hash] = str(file_path)
                file_hash_cache[str(file_path)] = file_hash
        except Exception:
            continue

    # Display duplicates
    for file_path, mod_date in duplicates:
        try:
            if str(file_path) in duplicate_paths:
                file_size = file_path.stat().st_size
                duplicates_treeview.insert("", tk.END, values=(file_path, mod_date, file_size))
        except (FileNotFoundError, PermissionError) as e:
            logging.error(f"Error processing duplicate {file_path}: {str(e)}")
            continue

    # Display only originals that have duplicates
    for file_path, mod_date in originals:
        try:
            if str(file_path) in hash_to_originals.values():
                file_size = file_path.stat().st_size
                originals_treeview.insert("", tk.END, values=(file_path, mod_date, file_size))
        except (FileNotFoundError, PermissionError) as e:
            logging.error(f"Error processing original {file_path}: {str(e)}")
            continue
    
    total_duplicates = len(duplicates)
    total_originals = len(originals)
    status_label.config(text=f"Found {total_duplicates} duplicates of {total_originals} original files")
    update_select_all_button_state()
    update_total_duplicate_size_label()

    scan_button.config(text="Scan")
    pause_button.grid_remove()
    refresh_button.config(state=tk.NORMAL)
    scanning = False
    # Reset progress bar and current file label
    progress_var.set(0)
    progress_bar.update()
    current_file_label.config(text="")

def update_select_all_button_state():
    if duplicates_treeview.get_children():
        select_all_button.config(state=tk.NORMAL)
    else:
        select_all_button.config(state=tk.DISABLED)

def on_delete():
    selected_items = duplicates_treeview.selection()
    
    # Safety check - don't delete originals
    original_paths = [originals_treeview.item(item, "values")[0] for item in originals_treeview.get_children()]
    selected_files = []
    skipped_files = []
    items_to_remove = []
    
    for item in selected_items:
        file_path = duplicates_treeview.item(item, "values")[0]
        if file_path not in original_paths:
            selected_files.append(file_path)
            items_to_remove.append(item)
        else:
            skipped_files.append(file_path)
    
    if skipped_files:
        messagebox.showwarning("Warning", f"Skipped {len(skipped_files)} original files that were selected for deletion.")
    
    if not selected_files:
        return
        
    # Store mapping of duplicates to originals before deletion
    report_mapping = []
    for file, item in zip(selected_files, items_to_remove):
        try:
            duplicate_path = Path(file)
            duplicate_hash = get_file_hash_md5(duplicate_path)
            if duplicate_hash is None:
                continue
                
            # Find original for this duplicate before deleting
            for orig_item in originals_treeview.get_children():
                original_path = Path(originals_treeview.item(orig_item, "values")[0])
                original_hash = get_file_hash_md5(original_path)
                if original_hash and original_hash == duplicate_hash:
                    report_mapping.append((str(duplicate_path), str(original_path)))
                    break
        except Exception as e:
            logging.error(f"Error mapping file {file}: {str(e)}")
            continue

    # Delete files and update UI
    try:
        delete_files(selected_files, progress_var, progress_bar)
        # Remove deleted items from treeview
        for item in items_to_remove:
            duplicates_treeview.delete(item)
    except Exception as e:
        logging.error(f"Error during deletion: {str(e)}")
        messagebox.showerror("Error", f"Error deleting files: {str(e)}")
        return

    # Generate report from stored mapping
    if report_mapping:
        report_text = "\n\n".join([f"Deleted: {deleted}\nOriginal: {original}" for deleted, original in report_mapping])
        messagebox.showinfo("Deletion Report", f"Deleted files and their originals:\n\n{report_text}")
    else:
        messagebox.showinfo("Deletion Report", "Files were deleted but original mapping could not be determined")

    status_label.config(text="Deletion complete.")
    update_total_duplicate_size_label()
    update_select_all_button_state()
    # Reset progress bar
    progress_var.set(0)
    progress_bar.update()

def on_cancel():
    global scanning, paused
    if scanning:
        scanning = False
        paused = False
        scan_button.config(text="Scan")
        pause_button.grid_remove()
        refresh_button.config(state=tk.NORMAL)
        status_label.config(text="Scanning stopped.")
    else:
        root.destroy()

def select_all():
    duplicates_treeview.update_idletasks()
    items = duplicates_treeview.get_children()
    if not items:
        return
        
    duplicates_treeview.configure(selectmode='none')
    
    try:
        duplicates_treeview.selection_set(items)
    finally:
        duplicates_treeview.configure(selectmode='extended')
        duplicates_treeview.update_idletasks()
    
    update_delete_button_state()
    update_space_saving_label()

def update_delete_button_state():
    if duplicates_treeview.selection():
        delete_button.config(state=tk.NORMAL)
    else:
        delete_button.config(state=tk.DISABLED)

def start_move(event):
    root.x = event.x
    root.y = event.y

def stop_move(event):
    root.x = None
    root.y = None

def on_move(event):
    deltax = event.x - root.x
    deltay = event.y - root.y
    x = root.winfo_x() + deltax
    y = root.winfo_y() + deltay
    root.geometry(f"+{x}+{y}")

def debounce(wait):
    """Decorator to debounce a function."""
    def decorator(fn):
        def debounced(*args, **kwargs):
            def call_it():
                fn(*args, **kwargs)
            
            if hasattr(debounced, 'after_id'):
                root.after_cancel(debounced.after_id)
            debounced.after_id = root.after(int(wait * 1000), call_it)
        return debounced
    return decorator

def calculate_hash_async(file_path, callback):
    """Calculate hash in background thread."""
    def _calculate():
        try:
            file_hash = get_file_hash_md5(Path(file_path))
            root.after(0, lambda: callback(file_hash))
        except Exception as e:
            logging.error(f"Error calculating hash: {str(e)}")
            root.after(0, lambda: callback(None))
            
    thread = threading.Thread(target=_calculate)
    thread.daemon = True
    thread.start()

def highlight_original(selected_duplicates):
    """Highlight the corresponding original files for the selected duplicates."""
    if not selected_duplicates:
        return
        
    try:
        original_items = originals_treeview.get_children()
        originals_treeview.selection_remove(original_items)
        
        # Get first selected duplicate's hash
        duplicate_path = selected_duplicates[0]
        file_hash = file_hash_cache.get(str(duplicate_path))
        
        if file_hash and file_hash in hash_to_originals:
            original_path = hash_to_originals[file_hash]
            for item in original_items:
                if originals_treeview.item(item, "values")[0] == original_path:
                    originals_treeview.selection_set(item)
                    originals_treeview.see(item)
                    break
    except Exception as e:
        logging.error(f"Error in highlight_original: {str(e)}")

def highlight_duplicates(selected_original):
    """Highlight all corresponding duplicate files for the selected original."""
    if not selected_original:
        return
        
    try:
        duplicate_items = duplicates_treeview.get_children()
        duplicates_treeview.selection_remove(duplicate_items)
        
        original_path = selected_original[0]
        file_hash = file_hash_cache.get(str(original_path))
        
        if file_hash and file_hash in hash_to_duplicates:
            # Select all duplicates for this original
            to_select = []
            for dup_path in hash_to_duplicates[file_hash]:
                for item in duplicate_items:
                    if duplicates_treeview.item(item, "values")[0] == dup_path:
                        to_select.append(item)
            
            if to_select:
                duplicates_treeview.selection_set(to_select)
                duplicates_treeview.see(to_select[0])
                # Update delete button and space saving label since we're selecting duplicates
                update_delete_button_state()
                update_space_saving_label()
    except Exception as e:
        logging.error(f"Error in highlight_duplicates: {str(e)}")

def on_original_click(event):
    """Handle click event on originals treeview."""
    region = originals_treeview.identify("region", event.x, event.y)
    if region == "cell":  # Only respond to cell clicks
        clicked_item = originals_treeview.identify_row(event.y)
        if clicked_item:
            # Clear previous selection and select clicked item
            originals_treeview.selection_set(clicked_item)
            # Get file path of clicked item
            file_path = originals_treeview.item(clicked_item, "values")[0]
            # Highlight all corresponding duplicates
            highlight_duplicates([file_path])

def on_duplicate_click(event):
    """Handle click event on duplicates treeview."""
    region = duplicates_treeview.identify("region", event.x, event.y)
    if region == "cell":  # Only respond to cell clicks
        clicked_item = duplicates_treeview.identify_row(event.y)
        if clicked_item:
            # Don't clear previous selection to allow multiple selections
            # Just highlight corresponding original based on current selection
            selected_items = duplicates_treeview.selection()
            selected_duplicates = [duplicates_treeview.item(item, "values")[0] for item in selected_items]
            if selected_duplicates:
                highlight_original(selected_duplicates)
            update_delete_button_state()
            update_space_saving_label()

@debounce(0.1)
def on_original_select(event):
    selected_items = originals_treeview.selection()
    selected_originals = [originals_treeview.item(item, "values")[0] for item in selected_items]
    if selected_originals:
        highlight_duplicates(selected_originals)

@debounce(0.1)
def on_duplicate_select(event):
    selected_items = duplicates_treeview.selection()
    if not selected_items:
        return
        
    selected_duplicates = [duplicates_treeview.item(item, "values")[0] for item in selected_items]
    if selected_duplicates:
        highlight_original(selected_duplicates)
    update_delete_button_state()
    update_space_saving_label()

def update_space_saving_label():
    """Update the label showing the potential space saving."""
    selected_items = duplicates_treeview.selection()
    selected_files = [Path(duplicates_treeview.item(item, "values")[0]) for item in selected_items]
    total_size = calculate_total_size(selected_files)
    space_saving_label.config(text=f"Potential Space Saving: {total_size / (1024 * 1024):.2f} MB")

def load_components():
    """Load all components with a progress bar."""
    steps = 10
    for i in range(steps):
        progress_var.set((i + 1) * (100 / steps))
        root.update_idletasks()
        root.after(100)

def start_scanning():
    global scanning, paused, remaining_files
    if scanning:
        scanning = False
        paused = False
        remaining_files = None
        scan_button.config(text="Scan")
        pause_button.grid_remove()
        refresh_button.config(state=tk.NORMAL)
        status_label.config(text="Scanning stopped.")
        current_file_label.config(text="")
    else:
        scanning = True
        paused = False
        remaining_files = None
        scan_button.config(text="Stop Scanning")
        pause_button.grid(row=1, column=1, pady=10, padx=20)
        refresh_button.config(state=tk.DISABLED)
        list_duplicates()

def pause_scanning():
    global paused
    if paused:
        paused = False
        pause_button.config(text="Pause Scanning")
        status_label.config(text="Scanning resumed...")
        list_duplicates()  # Continue scanning
    else:
        paused = True
        pause_button.config(text="Resume Scanning")
        status_label.config(text="Scanning paused. Current results shown.")

def update_total_duplicate_size_label():
    total_size = sum(int(duplicates_treeview.item(item, "values")[2]) for item in duplicates_treeview.get_children())
    total_duplicate_size_label.config(text=f"Total Duplicate Size: {total_size / (1024 * 1024):.2f} MB")

def export_to_csv():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return

    with open(file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["File Path", "Last Modified", "Size (Bytes)", "Type"])

        for item in originals_treeview.get_children():
            values = originals_treeview.item(item, "values")
            writer.writerow([values[0], values[1], values[2], "Original"])

        for item in duplicates_treeview.get_children():
            values = duplicates_treeview.item(item, "values")
            writer.writerow([values[0], values[1], values[2], "Duplicate"])

    messagebox.showinfo("Info", "Exported to CSV successfully.")

# Create the main window
root = tk.Tk()
root.title("Delete Newer Duplicates")
root.geometry("1024x800+0+0")  # Increased window size
root.overrideredirect(True)
root.resizable(True, True)

style = Style()
style.theme_use("clam")
style.configure("TFrame", background="#2e2e2e", borderwidth=0)
style.configure("TLabel", background="#2e2e2e", foreground="#ffffff", borderwidth=0)
style.configure("TButton", background="#0078d7", foreground="#ffffff", relief="flat", borderwidth=0)
style.configure("TEntry", fieldbackground="#1e1e1e", foreground="#ffffff", borderwidth=0, insertbackground="#ffffff")
style.configure("Treeview", background="#1e1e1e", foreground="#ffffff", fieldbackground="#1e1e1e", borderwidth=0)
style.configure("Treeview.Heading", background="#3a3a3a", foreground="#ffffff", borderwidth=0, highlightthickness=0)
style.configure("TProgressbar", troughcolor="#2e2e2e", borderwidth=0)
style.configure("Custom.Vertical.TScrollbar", background="#2e2e2e", troughcolor="#1e1e1e", borderwidth=0, arrowcolor="#ffffff")

root.config(bg="#2e2e2e", borderwidth=0)
frame = tk.Frame(root, bg="#2e2e2e", borderwidth=0)
frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.99, relheight=0.95)

folder_label = tk.Label(frame, text="Folder Path:", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
folder_label.grid(row=0, column=0, padx=10, pady=40, sticky='w')

folder_entry = tk.Entry(frame, font=("Segoe UI", 12), fg="#ffffff", bg="#1e1e1e", bd=0, insertbackground="#ffffff")
folder_entry.grid(row=0, column=1, padx=10, pady=40, sticky='ew')

browse_button = tk.Button(frame, text="Browse", command=browse_folder, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
browse_button.grid(row=0, column=2, padx=10, pady=40)

scan_button = tk.Button(frame, text="Scan", command=start_scanning, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
scan_button.grid(row=1, column=2, pady=10, padx=20)  # Increased padding

pause_button = tk.Button(frame, text="Pause Scanning", command=pause_scanning, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
pause_button.grid(row=1, column=1, pady=10, padx=20)  # Increased padding
pause_button.grid_remove()

refresh_button = tk.Button(frame, text="Refresh", command=refresh_folder, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
refresh_button.grid(row=1, column=0, pady=10, padx=20)  # Increased padding

export_button = tk.Button(frame, text="Export to CSV", command=export_to_csv, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
export_button.grid(row=1, column=3, pady=10, padx=20)  # Increased padding

originals_label = tk.Label(frame, text="Originals", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
originals_label.grid(row=2, column=0, columnspan=4, padx=10, pady=5, sticky='w')

columns = ("File Path", "Last Modified", "Size (Bytes)")

originals_frame = tk.Frame(frame, bg="#2e2e2e")
originals_frame.grid(row=3, column=0, columnspan=4, padx=10, pady=5, sticky='nsew')

originals_treeview = Treeview(originals_frame, columns=columns, show="headings", height=20)
originals_treeview.heading("File Path", text="File Path", anchor=tk.W)
originals_treeview.heading("Last Modified", text="Last Modified", anchor=tk.W)
originals_treeview.heading("Size (Bytes)", text="Size (Bytes)", anchor=tk.W)
originals_treeview.column("File Path", width=480)
originals_treeview.column("Last Modified", width=80)
originals_treeview.column("Size (Bytes)", width=80)
originals_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
originals_treeview.tag_configure('original', background='#1e1e1e')

originals_scrollbar = Scrollbar(originals_frame, orient="vertical", command=originals_treeview.yview, style="Custom.Vertical.TScrollbar")
originals_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
originals_treeview.configure(yscrollcommand=originals_scrollbar.set)
originals_treeview.bind('<ButtonRelease-1>', on_original_click)

duplicates_label = tk.Label(frame, text="Duplicates", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
duplicates_label.grid(row=4, column=0, columnspan=4, padx=10, pady=5, sticky='w')

duplicates_frame = tk.Frame(frame, bg="#2e2e2e")
duplicates_frame.grid(row=5, column=0, columnspan=4, padx=10, pady=5, sticky='nsew')

duplicates_treeview = Treeview(duplicates_frame, columns=columns, show="headings", height=20)
duplicates_treeview.heading("File Path", text="File Path", anchor=tk.W)
duplicates_treeview.heading("Last Modified", text="Last Modified", anchor=tk.W)
duplicates_treeview.heading("Size (Bytes)", text="Size (Bytes)", anchor=tk.W)
duplicates_treeview.column("File Path", width=480)
duplicates_treeview.column("Last Modified", width=80)
duplicates_treeview.column("Size (Bytes)", width=80)
duplicates_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
duplicates_treeview.bind('<ButtonRelease-1>', on_duplicate_click)

duplicates_scrollbar = Scrollbar(duplicates_frame, orient="vertical", command=duplicates_treeview.yview, style="Custom.Vertical.TScrollbar")
duplicates_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
duplicates_treeview.configure(yscrollcommand=duplicates_scrollbar.set)

progress_var = tk.DoubleVar()
progress_bar = Progressbar(frame, variable=progress_var, maximum=100)
progress_bar.grid(row=6, column=0, columnspan=4, padx=10, pady=10, sticky='ew')

status_label = tk.Label(frame, text="", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
status_label.grid(row=7, column=0, columnspan=4, pady=10)

current_file_label = tk.Label(frame, text="", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
current_file_label.grid(row=8, column=0, columnspan=4, pady=10)

select_all_button = tk.Button(frame, text="Select All", command=select_all, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
select_all_button.grid(row=9, column=0, pady=10)
select_all_button.config(state=tk.DISABLED)

delete_button = tk.Button(frame, text="Delete", command=on_delete, state=tk.DISABLED, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
delete_button.grid(row=9, column=1, pady=10)

cancel_button = tk.Button(frame, text="Cancel", command=on_cancel, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
cancel_button.grid(row=9, column=2, pady=10)

space_saving_label = tk.Label(frame, text="Potential Space Saving: 0.00 MB", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
space_saving_label.grid(row=10, column=0, columnspan=4, pady=10)

total_duplicate_size_label = tk.Label(frame, text="Total Duplicate Size: 0.00 MB", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
total_duplicate_size_label.grid(row=11, column=0, columnspan=4, pady=10)

title_frame = tk.Frame(root, bg="#2e2e2e", height=20, borderwidth=0)
title_frame.pack(fill=tk.X, side=tk.TOP)

title_label = tk.Label(title_frame, text="Delete Newer Duplicates", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
title_label.pack(side=tk.LEFT, padx=10)

close_button = tk.Button(title_frame, text="X", command=on_cancel, font=("Segoe UI", 12), bg="#ff0000", fg="#ffffff", bd=0, relief="flat", width=2, height=1)
close_button.pack(side=tk.RIGHT, padx=5, pady=5)

title_frame.bind("<ButtonPress-1>", start_move)
title_frame.bind("<ButtonRelease-1>", stop_move)
title_frame.bind("<B1-Motion>", on_move)

frame.grid_rowconfigure(3, weight=3)  # Increased weight for originals tree
frame.grid_rowconfigure(5, weight=3)  # Increased weight for duplicates tree
frame.grid_columnconfigure(1, weight=1)

frame.grid_rowconfigure(0, weight=0)  # Header area
frame.grid_rowconfigure(1, weight=0)  # Buttons area
frame.grid_rowconfigure(2, weight=0)  # Labels
frame.grid_rowconfigure(4, weight=0)  # Labels
frame.grid_rowconfigure(6, weight=0)  # Progress bar area
frame.grid_rowconfigure(7, weight=0)  # Status area
frame.grid_rowconfigure(8, weight=0)  # Current file area
frame.grid_rowconfigure(9, weight=0)  # Buttons area
frame.grid_rowconfigure(10, weight=0) # Labels
frame.grid_rowconfigure(11, weight=0) # Labels

last_path = load_last_path()
if last_path:
    folder_entry.insert(0, last_path)

load_components()

root.mainloop()
