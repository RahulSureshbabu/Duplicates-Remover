import subprocess
import os

# Set the path to your script relative to the current working directory
script_path = os.path.join(os.path.dirname(__file__), "DupeDeleteUI.py")

# Ensure the script path is correct
if not os.path.exists(script_path):
    print(f"Script not found: {script_path}")
    exit(1)

print("All files found successfully.")

# Show the current folder being searched
print(f"Searching in folder: {os.path.dirname(script_path)}")

# Run PyInstaller to create the executable
subprocess.run([
    "pyinstaller",
    "--onefile",
    "--windowed",
    script_path
])

# Inform the user where the executable can be found
print("Executable created successfully. You can find it in the 'dist' directory.")

# Inform the user that deletion is complete
print("Deletion complete.")
