# nCode - Secure Client-Side Encryption Tool

Developed by Jules.

## Overview

nCode is a web-based application designed for secure client-side encryption and password management. All operations, including string encryption, file encryption, and password generation, are performed directly in your browser. This means your sensitive data is never sent to a server, and you can download and run nCode offline if needed.

A key feature of nCode is **Goldhash**. This is a unique hash generated from your content (string or file) and your password, using a secure SHA-256 algorithm combined with an application-specific salt.
*   When you **encrypt** something, its Goldhash is displayed.
*   When you **decrypt** it, the Goldhash of the decrypted content is shown.
If the Goldhashes match, you can be confident that the content is identical and has not been altered, and that you've used the correct password.

## Features

### 1. String Encryption

*   **Functionality:** This tab allows you to encrypt any text string using a password of your choice. It also allows you to decrypt previously encrypted strings using the same password.
*   **Unique Encrypted Output:** The encryption process (AES-GCM) uses a unique initialization vector (IV) and salt each time, so the encrypted output for the same string and password will look different every time you encrypt it. This enhances security.
*   **Goldhash Verification:**
    *   Upon encryption, a "goldhash" of your *original string* and password is displayed.
    *   Upon successful decryption, a "goldhash" of the *decrypted string* and password is displayed.
    *   Compare these Goldhashes: if they match, it confirms the integrity and correctness of the decrypted content.
*   **Encryption Method:** Uses AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) for robust encryption, with PBKDF2 (Password-Based Key Derivation Function 2) and SHA-256 to derive a strong encryption key from your password.
*   **Client-Side:** All operations are performed in your browser.

### 2. Password Manager

*   **Functionality:** This tab helps you create strong, unique passwords for different websites or services. It generates these passwords deterministically based on a "Manager Password" you set and a "Site Name" you provide.
*   **Reproducible Passwords:** As long as you remember your Manager Password and the exact Site Name you used, you can always regenerate the same complex password for that site. This is useful if you forget a site-specific password but remember your Manager Password.
*   **How to Use:**
    1.  Enter a strong "Manager Password" (keep this one safe and memorable!).
    2.  For each site or service, enter a unique "Site Name" (e.g., "Google Account", "My Bank Login").
    3.  The tool will generate a strong password for each site.
*   **Storing Your Passwords:**
    *   The list of site names and their generated passwords can be copied from the result box.
    *   You can then take this list to the "String Encryption" tab, paste it, and encrypt it using your Manager Password (or another password of your choice) to create a secure, encrypted text block.
    *   For even more security, this encrypted text block (or a file containing it) can then be further encrypted using the "File Encryption" tab.
*   **Generation Method:** Uses SHA-256 to hash the combination of your Manager Password and the Site Name. The resulting hash is then used to deterministically construct a complex password meeting common criteria (uppercase, lowercase, numbers, symbols).

### 3. File Encryption

*   **Functionality:** This tab allows you to encrypt any file from your computer using a password. The encrypted file can then be decrypted using the same password.
*   **Client-Side Processing:** The file is selected and processed entirely within your browser. It is not uploaded to any server.
*   **Output:** Encrypted files are downloaded with the `.nCode` file extension (e.g., `nCode_encrypted_myfile.txt.nCode`).
*   **Original File Safety:** Your original file remains untouched on your system. The encryption process creates a new, encrypted version of it.
*   **Goldhash Verification:**
    *   When you select a file and password for **encryption**, a "goldhash" of the *original file's content* and the password is displayed.
    *   When you select an encrypted file and password for **decryption**, and the decryption is successful, a "goldhash" of the *decrypted file's content* and the password is displayed.
    *   Matching Goldhashes confirm that the file has been decrypted correctly and its content is intact.
*   **Encryption Method:** Uses AES-GCM for strong, authenticated encryption of file content. Files are processed in chunks to handle larger files efficiently. A unique salt and IV are used for each encryption session, and PBKDF2 with SHA-256 derives the encryption key from your password. This method is secure enough to handle brute-force attempts effectively.

## Offline Usage

Since all operations are client-side, you can download the nCode application (the HTML file and associated `scripts` and `assets` folders) and run it from your local computer without an internet connection.

---
Feel free to contribute or report issues!
