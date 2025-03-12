import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar, Treeview, Style
from pathlib import Path
import os
import sys
import logging
import time
import csv

# Ensure the current directory is in the Python path
sys.path.append(os.path.dirname(__file__))

from DupeDeleteLogic import (
    find_duplicates,
    delete_files,
    calculate_total_size,
    save_last_path,
    load_last_path,
    get_file_hash_sha256
)

# Log the current working directory for debugging
logging.basicConfig(level=logging.INFO)
logging.info(f"Current working directory: {os.getcwd()}")

scanning = False
start_time = None
paused = False
pause_button = None

def browse_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder_path)
        save_last_path(folder_path)
        list_duplicates()

def refresh_folder():
    list_duplicates()

def list_duplicates():
    global scanning, start_time, paused
    if not scanning:
        return

    folder_path = folder_entry.get()
    progress_var.set(0)
    status_label.config(text=f"Searching in folder: {folder_path}")
    start_time = time.time()
    
    # Ensure Treeview widgets are initialized before using them
    if duplicates_treeview.winfo_exists() and originals_treeview.winfo_exists():
        duplicates_treeview.delete(*duplicates_treeview.get_children())
        originals_treeview.delete(*originals_treeview.get_children())

        def update_display_callback(file_path, mod_date):
            if not scanning or paused:
                return
            file_size = file_path.stat().st_size
            duplicates_treeview.insert("", tk.END, values=(file_path, mod_date, file_size))
            originals_treeview.insert("", tk.END, values=(file_path, mod_date, file_size))
            update_delete_button_state()

        duplicates, originals = find_duplicates(folder_path, progress_var, progress_bar, update_display_callback)
        
        # Display only files that have duplicates
        for file_path, mod_date in duplicates:
            if not scanning or paused:
                break
            file_size = file_path.stat().st_size
            duplicates_treeview.insert("", tk.END, values=(file_path, mod_date, file_size))
        for file_path, mod_date in originals:
            if not scanning or paused:
                break
            file_size = file_path.stat().st_size
            originals_treeview.insert("", tk.END, values=(file_path, mod_date, file_size))
        
        total_files_found = len(duplicates) + len(originals)
        status_label.config(text=f"Total files found: {total_files_found}")
        update_select_all_button_state()
        update_total_duplicate_size_label()
    else:
        status_label.config(text="Error: Treeview widgets not initialized.")

    scan_button.config(text="Scan")
    pause_button.grid_remove()
    refresh_button.config(state=tk.NORMAL)
    scanning = False

def update_select_all_button_state():
    if duplicates_treeview.get_children():
        select_all_button.config(state=tk.NORMAL)
    else:
        select_all_button.config(state=tk.DISABLED)

def find_duplicates(folder_path, progress_var, progress_bar, update_display_callback):
    """Find duplicate files in a folder and its subfolders, keeping only the oldest file."""
    if not os.path.exists(folder_path):
        print(f"Folder not found: {folder_path}")
        return [], []

    file_hashes = {}
    duplicates = []
    originals = []
    total_files = sum([len(files) for _, _, files in os.walk(folder_path)])
    processed_files = 0

    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            if not scanning:
                break
            while paused:
                root.update()
                time.sleep(0.1)
            full_path = Path(root_dir) / file
            file_hash = get_file_hash_sha256(full_path)
            file_modified_date = full_path.stat().st_mtime

            if file_hash in file_hashes:
                stored_file = file_hashes[file_hash]
                if file_modified_date > stored_file['date']:
                    duplicates.append((full_path, file_modified_date))
                    originals.append((stored_file['path'], stored_file['date']))
                else:
                    duplicates.append((stored_file['path'], stored_file['date']))
                    file_hashes[file_hash] = {'path': full_path, 'date': file_modified_date}
                    originals.append((full_path, file_modified_date))
            else:
                file_hashes[file_hash] = {'path': full_path, 'date': file_modified_date}

            processed_files += 1
            progress_var.set((processed_files / total_files) * 100)
            progress_bar.update()

            elapsed_time = time.time() - start_time
            estimated_total_time = (elapsed_time / processed_files) * total_files
            remaining_time = estimated_total_time - elapsed_time
            remaining_time_struct = time.gmtime(remaining_time)
            remaining_time_str = time.strftime("%H:%M:%S", remaining_time_struct)
            status_label.config(text=f"Estimated time remaining: {remaining_time_str}")
            current_file_label.config(text=f"Scanning: {full_path}")

    return duplicates, originals

def on_delete():
    selected_items = duplicates_treeview.selection()
    selected_files = [duplicates_treeview.item(item, "values")[0] for item in selected_items]
    delete_files(selected_files, progress_var, progress_bar)
    
    # Generate report of deleted files and their original locations
    report = []
    for file in selected_files:
        duplicate_path = Path(file)
        duplicate_hash = get_file_hash_sha256(duplicate_path)
        for item in originals_treeview.get_children():
            original_path = Path(originals_treeview.item(item, "values")[0])
            if get_file_hash_sha256(original_path) == duplicate_hash:
                report.append((file, str(original_path)))
                break

    # Show report in a message box
    report_text = "\n".join([f"Deleted: {deleted}\nOriginal: {original}" for deleted, original in report])
    messagebox.showinfo("Deletion Report", f"Deleted files and their originals:\n\n{report_text}")

    list_duplicates()
    status_label.config(text="Deletion complete.")
    update_total_duplicate_size_label()

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
    duplicates_treeview.selection_set(duplicates_treeview.get_children())
    update_delete_button_state()

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

def highlight_original(selected_duplicates):
    """Highlight the corresponding original files for the selected duplicates."""
    original_items = originals_treeview.get_children()
    originals_treeview.selection_remove(original_items)
    for selected_duplicate in selected_duplicates:
        duplicate_path = Path(selected_duplicate)
        duplicate_hash = get_file_hash_sha256(duplicate_path)
        for item in original_items:
            original_path = Path(originals_treeview.item(item, "values")[0])
            if get_file_hash_sha256(original_path) == duplicate_hash:
                originals_treeview.selection_add(item)
                originals_treeview.see(item)

def update_space_saving_label():
    """Update the label showing the potential space saving."""
    selected_items = duplicates_treeview.selection()
    selected_files = [Path(duplicates_treeview.item(item, "values")[0]) for item in selected_items]
    total_size = calculate_total_size(selected_files)
    space_saving_label.config(text=f"Potential Space Saving: {total_size / (1024 * 1024):.2f} MB")

def on_duplicate_select(event):
    selected_items = duplicates_treeview.selection()
    selected_duplicates = [duplicates_treeview.item(item, "values")[0] for item in selected_items]
    if selected_duplicates:
        highlight_original(selected_duplicates)
    update_delete_button_state()
    update_space_saving_label()

def load_components():
    """Load all components with a progress bar."""
    steps = 10
    for i in range(steps):
        progress_var.set((i + 1) * (100 / steps))
        root.update_idletasks()
        # Simulate loading time
        root.after(100)

def start_scanning():
    global scanning, paused
    if scanning:
        scanning = False
        paused = False
        scan_button.config(text="Scan")
        pause_button.grid_remove()
        refresh_button.config(state=tk.NORMAL)
        status_label.config(text="Scanning stopped.")
    else:
        scanning = True
        paused = False
        scan_button.config(text="Stop Scanning")
        pause_button.grid(row=1, column=1, pady=10, padx=20)  # Increased padding
        refresh_button.config(state=tk.DISABLED)
        list_duplicates()

def pause_scanning():
    global paused
    if paused:
        paused = False
        pause_button.config(text="Pause Scanning")
        status_label.config(text="Scanning resumed.")
    else:
        paused = True
        pause_button.config(text="Resume Scanning")
        status_label.config(text="Scanning paused.")

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
root.geometry("800x650+0+0")  # Start in the top left corner
root.overrideredirect(True)
root.resizable(True, True)

# Remove centering the window on the screen
# root.eval('tk::PlaceWindow . center')

# Apply a dark theme
style = Style()
style.theme_use("clam")
style.configure("TFrame", background="#2e2e2e", borderwidth=0)
style.configure("TLabel", background="#2e2e2e", foreground="#ffffff", borderwidth=0)
style.configure("TButton", background="#0078d7", foreground="#ffffff", relief="flat", borderwidth=0)
style.configure("TEntry", fieldbackground="#1e1e1e", foreground="#ffffff", borderwidth=0, insertbackground="#ffffff")
style.configure("Treeview", background="#1e1e1e", foreground="#ffffff", fieldbackground="#1e1e1e", borderwidth=0)
style.configure("Treeview.Heading", background="#3a3a3a", foreground="#ffffff", borderwidth=0, highlightthickness=0)
style.configure("TProgressbar", troughcolor="#2e2e2e", borderwidth=0)

# Create a rounded rectangle window without a border
root.config(bg="#2e2e2e", borderwidth=0)
frame = tk.Frame(root, bg="#2e2e2e", borderwidth=0)
frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.99, relheight=0.95)

# Create and place the widgets
folder_label = tk.Label(frame, text="Folder Path:", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
folder_label.grid(row=0, column=0, padx=10, pady=40, sticky='w')

folder_entry = tk.Entry(frame, font=("Segoe UI", 12), fg="#ffffff", bg="#1e1e1e", bd=0, insertbackground="#ffffff")
folder_entry.grid(row=0, column=1, padx=10, pady=40, sticky='ew')

browse_button = tk.Button(frame, text="Browse", command=browse_folder, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
browse_button.grid(row=0, column=2, padx=10, pady=40)

# Add a new button for scanning
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
originals_treeview = Treeview(frame, columns=columns, show="headings", height=20)  # Set height to 20
originals_treeview.heading("File Path", text="File Path", anchor=tk.W)
originals_treeview.heading("Last Modified", text="Last Modified", anchor=tk.W)
originals_treeview.heading("Size (Bytes)", text="Size (Bytes)", anchor=tk.W)
originals_treeview.column("File Path", width=480)
originals_treeview.column("Last Modified", width=80)
originals_treeview.column("Size (Bytes)", width=80)
originals_treeview.grid(row=3, column=0, columnspan=4, padx=10, pady=5, sticky='nsew')
originals_treeview.tag_configure('original', background='#1e1e1e')

originals_scrollbar = tk.Scrollbar(frame, orient="vertical", command=originals_treeview.yview, bg="#2e2e2e", troughcolor="#2e2e2e")
originals_treeview.configure(yscrollcommand=originals_scrollbar.set)
originals_scrollbar.grid(row=3, column=4, sticky='ns')

duplicates_label = tk.Label(frame, text="Duplicates", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
duplicates_label.grid(row=4, column=0, columnspan=4, padx=10, pady=5, sticky='w')

duplicates_treeview = Treeview(frame, columns=columns, show="headings", height=20)  # Set height to 20
duplicates_treeview.heading("File Path", text="File Path", anchor=tk.W)
duplicates_treeview.heading("Last Modified", text="Last Modified", anchor=tk.W)
duplicates_treeview.heading("Size (Bytes)", text="Size (Bytes)", anchor=tk.W)
duplicates_treeview.column("File Path", width=480)
duplicates_treeview.column("Last Modified", width=80)
duplicates_treeview.column("Size (Bytes)", width=80)
duplicates_treeview.grid(row=5, column=0, columnspan=4, padx=10, pady=5, sticky='nsew')
duplicates_treeview.bind('<<TreeviewSelect>>', on_duplicate_select)

duplicates_scrollbar = tk.Scrollbar(frame, orient="vertical", command=duplicates_treeview.yview, bg="#2e2e2e", troughcolor="#2e2e2e")
duplicates_treeview.configure(yscrollcommand=duplicates_scrollbar.set)
duplicates_scrollbar.grid(row=5, column=4, sticky='ns')

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

# Add a close button and title at the top
title_frame = tk.Frame(root, bg="#2e2e2e", height=20, borderwidth=0)
title_frame.pack(fill=tk.X, side=tk.TOP)

title_label = tk.Label(title_frame, text="Delete Newer Duplicates", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
title_label.pack(side=tk.LEFT, padx=10)

close_button = tk.Button(title_frame, text="X", command=on_cancel, font=("Segoe UI", 12), bg="#ff0000", fg="#ffffff", bd=0, relief="flat", width=2, height=1)
close_button.pack(side=tk.RIGHT, padx=5, pady=5)

# Bind the move functions to the title frame
title_frame.bind("<ButtonPress-1>", start_move)
title_frame.bind("<ButtonRelease-1>", stop_move)
title_frame.bind("<B1-Motion>", on_move)

# Make the UI scalable
frame.grid_rowconfigure(3, weight=1)
frame.grid_rowconfigure(5, weight=1)
frame.grid_columnconfigure(1, weight=1)

# Load the last opened path on startup
last_path = load_last_path()
if last_path:
    folder_entry.insert(0, last_path)
    # Remove the call to list_duplicates() here

# Load components with progress bar
load_components()

# Run the application
root.mainloop()
