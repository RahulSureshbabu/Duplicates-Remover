*** Settings ***
Library           OperatingSystem
Library           Collections
Library           BuiltIn
Library           Process
Library           SeleniumLibrary

*** Variables ***
${TEST_FOLDER}    ${CURDIR}/test_folder
${BROWSER}        chrome
${URL}            file://${CURDIR}/../DupeDeleteUI.py

*** Test Cases ***
Setup Test Folder
    [Documentation]    Create a test folder with some files for testing.
    Create Directory    ${TEST_FOLDER}
    Create File    ${TEST_FOLDER}/file1.txt    Content 1
    Create File    ${TEST_FOLDER}/file2.txt    Content 2
    Create File    ${TEST_FOLDER}/file1_copy.txt    Content 1

Open Application
    [Documentation]    Open the application in a browser.
    Open Browser    ${URL}    ${BROWSER}
    Maximize Browser Window

Test Browse Folder
    [Documentation]    Test the browse folder functionality.
    Click Button    Browse
    Input Text    Folder Path    ${TEST_FOLDER}
    Click Button    Refresh
    Page Should Contain    file1.txt
    Page Should Contain    file2.txt
    Page Should Contain    file1_copy.txt

Test Select All Duplicates
    [Documentation]    Test the select all duplicates functionality.
    Click Button    Select All
    ${selected_items}=    Get Selected Items    duplicates_treeview
    Length Should Be    ${selected_items}    1

Test Delete Duplicates
    [Documentation]    Test the delete duplicates functionality.
    Click Button    Delete
    Page Should Not Contain    file1_copy.txt

Teardown Test Folder
    [Documentation]    Remove the test folder after testing.
    Remove Directory    ${TEST_FOLDER}    recursive=True

Close Application
    [Documentation]    Close the browser.
    Close Browser
