# Running Tests

## Prerequisites

1. Install Robot Framework:
    ```sh
    pip install robotframework
    ```

2. Install SeleniumLibrary for Robot Framework:
    ```sh
    pip install robotframework-seleniumlibrary
    ```

3. Install a web driver for your browser (e.g., ChromeDriver for Chrome):
    - [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/downloads)

## Running the Tests

1. Navigate to the `tests` directory:
    ```sh
    cd /c:/rData/Python/DuplicatesRemoverProject/tests
    ```

2. Run the tests:
    ```sh
    robot test_DupeDeleteLogic.robot
    robot test_DupeDeleteUI.robot
    ```

This will execute the tests for both the logic and UI components of the Duplicates Remover Project.
