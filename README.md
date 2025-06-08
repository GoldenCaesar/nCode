# nCode - Secure Client-Side Encryption Tool

Developed by GoldenCaesar with help from Jules. Thanks Jules.

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

### 4. Transmission Encryption

*   **Overview/Functionality:**
    *   **Purpose:** Enables the secure exchange of information (text strings and/or files) between two parties using asymmetric encryption. This method relies on public/private key pairs, allowing you to send data to someone securely or receive data from them with confidence.
    *   **Core Components:** The process involves:
        1.  Generating your own unique RSA key pair (a public key and a private key).
        2.  Sharing your public key with others.
        3.  Encrypting data using a recipient's public key.
        4.  Decrypting received data using your own private key.

*   **Key Pair Management:**
    *   **Generation:** Users generate their RSA key pairs (2048-bit) through the nCode interface. The private key is stored in an encrypted format within a downloadable file named `.nCodeKeys`.
    *   **Private Key Security:** The private key inside the `.nCodeKeys` file is itself encrypted using AES-GCM, with the encryption key derived from a user-chosen passphrase via PBKDF2 (SHA-256).
    *   **Loading Keys:** To use an existing key pair, you upload your `.nCodeKeys` file and provide the passphrase used during its creation. This decrypts your private key for use in the current session.
    *   **Goldhash for Key File:**
        *   **At Generation:** When you first generate your key pair, a Goldhash is created from your *public key (in JWK format)* and the *passphrase you set*. This Goldhash is displayed to you. It's recommended to save this Goldhash securely, separate from the `.nCodeKeys` file and passphrase.
        *   **At Load:** When you load an existing `.nCodeKeys` file and enter your passphrase, a Goldhash is recalculated using the *public key (read from the file)* and the *passphrase you just entered*.
        *   **Purpose:** If the Goldhash displayed at load time matches the Goldhash generated when the key pair was created (or last successfully loaded), it provides strong assurance that:
            1.  You have entered the correct passphrase.
            2.  The `.nCodeKeys` file is the one corresponding to that passphrase.
            3.  The public key component within the `.nCodeKeys` file has not been tampered with since the original Goldhash was noted.
    *   **Sharing Your Public Key:** You can copy your public key (in standard JWK JSON format) from the interface to share with others. This allows them to encrypt information specifically for you.
    *   **Security:** It is paramount to keep your `.nCodeKeys` file secure and your passphrase secret. Anyone with access to both can decrypt messages intended for you.

*   **nCode Mode (Encrypting a Transmission - Sending):**
    *   **Steps:**
        1.  Ensure your own key pair is generated and loaded if you wish to also manage your keys (optional for sending-only, but good practice).
        2.  Select the "nCode" (Transmission) mode.
        3.  Obtain the recipient's public key (as a JWK JSON string). This must be shared with you by the intended recipient.
        4.  Paste the recipient's public key into the designated field.
        5.  Enter the text string you wish to send and/or select the file(s) to include in the transmission.
        6.  Click "Encrypt & Download Transmission".
    *   **Behind the Scenes:**
        *   A cryptographically strong one-time symmetric session key (AES-GCM 256-bit) is generated.
        *   If files are included, they are bundled together (e.g., into a zip archive internally). The string data and file bundle are then encrypted using this session key.
        *   The session key itself is then encrypted using the recipient's RSA public key (using RSA-OAEP with SHA-256).
        *   The output is a `.nCodeTransmission` file. This JSON-formatted file contains the encrypted data blob, the encrypted session key, necessary initialization vectors (IVs), and other metadata.
    *   **Goldhash for Transmission (Sender-Side):**
        *   **Generation:** A Goldhash is generated from the *original content (plaintext string, or a manifest/concatenation of file names if multiple files, or the single file's raw content)* and the *Recipient's Public Key (the JWK string you pasted)*.
        *   This Goldhash is displayed to you (the sender) after encryption.
        *   **Purpose:** You should communicate this Goldhash value securely to the recipient through a separate, trusted channel (e.g., a different messaging app, verbally). This allows the recipient to verify the integrity and authenticity of the transmission upon decryption.
    *   **Decryption:** Only the person holding the private key corresponding to the public key used for encryption can decrypt the session key and, subsequently, the data.

*   **dCode Mode (Decrypting a Transmission - Receiving):**
    *   **Steps:**
        1.  Select the "dCode" (Transmission) mode.
        2.  Load your key pair: Upload your `.nCodeKeys` file and enter your passphrase.
        3.  Verify that the Goldhash displayed for your key file matches the one you noted when your keys were generated or last successfully loaded. This confirms you're using the correct passphrase and key file.
        4.  Select the received `.nCodeTransmission` file provided by the sender.
        5.  The application will automatically attempt to decrypt the transmission.
    *   **Behind the Scenes:**
        *   Your private key (decrypted from `.nCodeKeys` using your passphrase) is used to decrypt the RSA-encrypted session key found within the `.nCodeTransmission` file.
        *   This decrypted session key is then used to decrypt the actual data bundle (text and/or files) using AES-GCM.
        *   The decrypted string (if any) is displayed, and links to download the decrypted files (if any) are provided.
    *   **Goldhash for Transmission (Recipient-Side):**
        *   **Generation:** After successful decryption, a Goldhash is generated from the *decrypted content (the plaintext string or files)* and *your own Public Key (JWK string from your loaded `.nCodeKeys` file)*.
        *   This Goldhash is displayed to you (the recipient).
        *   **Purpose:** You compare this Goldhash with the Goldhash value provided out-of-band by the sender. A match confirms:
            *   **Content Integrity:** The decrypted content is exactly what the sender encrypted.
            *   **Correct Key Usage (Sender):** The sender used your intended public key.
            *   **Correct Key Usage (Recipient):** You have used the correct private key to decrypt.
    *   **Failure:** Decryption will fail if the wrong private key is used (i.e., the `.nCodeTransmission` file was not encrypted for your public key) or if the incorrect passphrase for your `.nCodeKeys` file is entered.

*   **Security Considerations / How it Works (Briefly):**
    *   **Asymmetric Encryption:** RSA-OAEP (using SHA-256) is employed for encrypting the symmetric session key.
    *   **Symmetric Encryption:** AES-GCM (256-bit) provides strong, authenticated encryption for the actual string and file data.
    *   **Passphrase Protection:** PBKDF2 (with SHA-256 and a salt) is used to derive a strong key from your passphrase, which then encrypts your private key within the `.nCodeKeys` file using AES-GCM.
    *   **Client-Side Operations:** All cryptographic operations, including key generation and data encryption/decryption, occur directly in your browser. No keys or unencrypted data are ever sent to a server.
    *   **Strong Passphrase:** The security of your private key in the `.nCodeKeys` file heavily relies on the strength of your chosen passphrase. Use a long, complex, and unique passphrase.
    *   **Sharing Public Keys:** Share your public key (the JWK JSON text) openly. It's designed to be public. **Never share your `.nCodeKeys` file or your passphrase.**
    *   **Sharing Transmission Goldhashes:** For the Goldhash verification of a transmission to be meaningful, the sender must communicate it to the recipient via a separate, trusted channel that is different from how the `.nCodeTransmission` file itself is sent. This prevents an attacker who might intercept the transmission file from also providing a fraudulent Goldhash.

## Offline Usage

Since all operations are client-side, you can download the nCode application (the HTML file and associated `scripts` and `assets` folders) and run it from your local computer without an internet connection.

## Important Note on Versioning

Please be aware that nCode is an evolving project. Future updates, especially those involving changes to the underlying encryption or decryption algorithms (indicated by a change in the version number visible in the site footer), may result in incompatibility with data encrypted with older versions.

**This means that text, files, or passwords encrypted with one version of nCode may not be decryptable or recoverable with a different version if the core algorithms have changed.**

It is crucial to keep a record of the version of nCode used for any specific encryption task if you anticipate needing to decrypt it in the distant future. While we strive for backward compatibility where possible, it cannot be guaranteed across major algorithm changes.

---
Feel free to contribute or report issues!
