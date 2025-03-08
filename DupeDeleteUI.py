import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar, Treeview, Style
from pathlib import Path
import os
import sys

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

# Print the current working directory for debugging
print("Current working directory:", os.getcwd())

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
    folder_path = folder_entry.get()
    progress_var.set(0)
    duplicates, originals = find_duplicates(folder_path, progress_var, progress_bar)
    for row in duplicates_treeview.get_children():
        duplicates_treeview.delete(row)
    for file, mod_date in duplicates:
        file_size = file.stat().st_size
        duplicates_treeview.insert("", tk.END, values=(file, mod_date, file_size))
    for row in originals_treeview.get_children():
        originals_treeview.delete(row)
    for file, mod_date in originals:
        file_size = file.stat().st_size
        originals_treeview.insert("", tk.END, values=(file, mod_date, file_size))
    update_delete_button_state()

def on_delete():
    selected_items = duplicates_treeview.selection()
    selected_files = [duplicates_treeview.item(item, "values")[0] for item in selected_items]
    delete_files(selected_files, progress_var, progress_bar)
    messagebox.showinfo("Info", "Selected duplicate files deleted.")
    list_duplicates()

def on_cancel():
    root.destroy()

def select_all():
    for item in duplicates_treeview.get_children():
        duplicates_treeview.selection_add(item)
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

# Create the main window
root = tk.Tk()
root.title("Delete Newer Duplicates")
root.geometry("800x650")
root.overrideredirect(True)
root.resizable(True, True)

# Center the window on the screen
root.eval('tk::PlaceWindow . center')

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

refresh_button = tk.Button(frame, text="Refresh", command=refresh_folder, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
refresh_button.grid(row=1, column=1, pady=10)

originals_label = tk.Label(frame, text="Originals", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
originals_label.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky='w')

columns = ("File Path", "Last Modified", "Size (Bytes)")
originals_treeview = Treeview(frame, columns=columns, show="headings")
originals_treeview.heading("File Path", text="File Path", anchor=tk.W)
originals_treeview.heading("Last Modified", text="Last Modified", anchor=tk.W)
originals_treeview.heading("Size (Bytes)", text="Size (Bytes)", anchor=tk.W)
originals_treeview.column("File Path", width=480)
originals_treeview.column("Last Modified", width=80)
originals_treeview.column("Size (Bytes)", width=80)
originals_treeview.grid(row=3, column=0, columnspan=3, padx=10, pady=5, sticky='nsew')
originals_treeview.tag_configure('original', background='#1e1e1e')

duplicates_label = tk.Label(frame, text="Duplicates", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
duplicates_label.grid(row=4, column=0, columnspan=3, padx=10, pady=5, sticky='w')

duplicates_treeview = Treeview(frame, columns=columns, show="headings")
duplicates_treeview.heading("File Path", text="File Path", anchor=tk.W)
duplicates_treeview.heading("Last Modified", text="Last Modified", anchor=tk.W)
duplicates_treeview.heading("Size (Bytes)", text="Size (Bytes)", anchor=tk.W)
duplicates_treeview.column("File Path", width=480)
duplicates_treeview.column("Last Modified", width=80)
duplicates_treeview.column("Size (Bytes)", width=80)
duplicates_treeview.grid(row=5, column=0, columnspan=3, padx=10, pady=5, sticky='nsew')
duplicates_treeview.bind('<<TreeviewSelect>>', on_duplicate_select)

progress_var = tk.DoubleVar()
progress_bar = Progressbar(frame, variable=progress_var, maximum=100)
progress_bar.grid(row=6, column=0, columnspan=3, padx=10, pady=10, sticky='ew')

select_all_button = tk.Button(frame, text="Select All", command=select_all, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
select_all_button.grid(row=7, column=0, pady=10)

delete_button = tk.Button(frame, text="Delete", command=on_delete, state=tk.DISABLED, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
delete_button.grid(row=7, column=1, pady=10)

cancel_button = tk.Button(frame, text="Cancel", command=on_cancel, font=("Segoe UI", 12), bg="#0078d7", fg="#ffffff", bd=0, relief="flat")
cancel_button.grid(row=7, column=2, pady=10)

space_saving_label = tk.Label(frame, text="Potential Space Saving: 0.00 MB", font=("Segoe UI", 12), bg="#2e2e2e", fg="#ffffff", borderwidth=0)
space_saving_label.grid(row=8, column=0, columnspan=3, pady=10)

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
    list_duplicates()

# Run the application
root.mainloop()
