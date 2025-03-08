# Duplicates Remover Project

## Features

- **Find Duplicates**: Scans a folder and its subfolders to find duplicate files based on their SHA-256 hash.
- **Delete Newer Duplicates**: Keeps the oldest file and lists newer duplicates for deletion.
- **Highlight Originals**: Highlights the corresponding original file when a duplicate is selected.
- **Calculate Space Saving**: Calculates and displays the potential space saving when selected duplicates are deleted.
- **Remember Last Path**: Remembers the last opened folder path between sessions.
- **Resizable Columns**: Allows resizing of columns in the file list views.
- **Dark Theme**: Provides a dark-themed user interface.
- **Executable Generation**: Generates a standalone executable using PyInstaller.

## Installation

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd DuplicatesRemoverProject
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Run the application:
    ```sh
    python DupeDeleteUI.py
    ```

2. Generate an executable:
    ```sh
    python GenerateExecutable.py
    ```

## How to Use

1. **Browse and Select Folder**:
    - Click the "Browse" button to select a folder to scan for duplicates.
    - The selected folder path will be displayed in the entry box.

2. **Refresh Folder**:
    - Click the "Refresh" button to update the list of duplicates and originals.

3. **View Duplicates and Originals**:
    - The "Originals" section lists the oldest files.
    - The "Duplicates" section lists the newer duplicate files.

4. **Select Duplicates**:
    - Click on a duplicate file to highlight the corresponding original file.
    - You can select multiple duplicates by holding the `Ctrl` key (Windows) or `Cmd` key (Mac) while clicking.

5. **Calculate Space Saving**:
    - The potential space saving is displayed at the bottom when duplicates are selected.

6. **Delete Duplicates**:
    - Click the "Delete" button to delete the selected duplicate files.
    - A confirmation message will be displayed after deletion.

7. **Select All Duplicates**:
    - Click the "Select All" button to select all duplicate files.

8. **Close the Application**:
    - Click the "X" button at the top right corner to close the application.

## Notes

- The application remembers the last opened folder path between sessions.
- The columns in the file list views are resizable.
- The application uses a dark theme for better visual comfort.


## License

This project is licensed under the MIT License.
