*** Settings ***
Library           OperatingSystem
Library           Collections
Library           BuiltIn
Library           Process
Library           ../DupeDeleteLogic.py

*** Variables ***
${TEST_FOLDER}    ${CURDIR}/test_folder

*** Test Cases ***
Setup Test Folder
    [Documentation]    Create a test folder with some files for testing.
    Create Directory    ${TEST_FOLDER}
    Create File    ${TEST_FOLDER}/file1.txt    Content 1
    Create File    ${TEST_FOLDER}/file2.txt    Content 2
    Create File    ${TEST_FOLDER}/file1_copy.txt    Content 1

Test Find Duplicates
    [Documentation]    Test the find_duplicates function.
    ${progress_var}=    Create List
    ${progress_bar}=    Create List
    ${duplicates}=    ${originals}=    Find Duplicates    ${TEST_FOLDER}    ${progress_var}    ${progress_bar}
    Length Should Be    ${duplicates}    1
    Length Should Be    ${originals}    2

Test Delete Files
    [Documentation]    Test the delete_files function.
    ${progress_var}=    Create List
    ${progress_bar}=    Create List
    ${files}=    Create List    ${TEST_FOLDER}/file1_copy.txt
    Delete Files    ${files}    ${progress_var}    ${progress_bar}
    File Should Not Exist    ${TEST_FOLDER}/file1_copy.txt

Test Calculate Total Size
    [Documentation]    Test the calculate_total_size function.
    ${files}=    Create List    ${TEST_FOLDER}/file1.txt    ${TEST_FOLDER}/file2.txt
    ${total_size}=    Calculate Total Size    ${files}
    Should Be True    ${total_size} > 0

Teardown Test Folder
    [Documentation]    Remove the test folder after testing.
    Remove Directory    ${TEST_FOLDER}    recursive=True
