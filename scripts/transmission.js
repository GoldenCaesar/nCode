let currentKeyPair = null;
let uploadedKeyFileData = null;

// Helper function to convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Helper function to convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// Helper function to trigger file download
function downloadFile(content, fileName, contentType) {
    const a = document.createElement("a");
    const file = new Blob([content], { type: contentType });
    a.href = URL.createObjectURL(file);
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(a.href);
}

async function generateAndEncryptKeys() {
    const keyGenPassphraseInput = document.getElementById('keyGenPassphraseInput');
    const loadedPublicKeyDisplay = document.getElementById('loadedPublicKeyDisplay'); // This ID was from the plan, but in HTML it's 'public-key-display-area'
    const publicKeyDisplayArea = document.getElementById('public-key-display-area'); // Corrected ID
    const copyPublicKeyButton = document.getElementById('copyPublicKeyButton');

    if (!keyGenPassphraseInput || !publicKeyDisplayArea || !copyPublicKeyButton) {
        alert("Required UI elements for key generation are missing. Please check the page structure.");
        return;
    }

    const passphrase = keyGenPassphraseInput.value;
    if (!passphrase) {
        alert("Please enter a passphrase to encrypt the keys.");
        return;
    }

    try {
        // Generate RSA Key Pair
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
                hash: "SHA-256"
            },
            true, // extractable
            ["encrypt", "decrypt"]
        );

        // Generate Salt for PBKDF2
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const kdfIterations = 100000;

        // Derive Symmetric Key (PBKDF2)
        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(passphrase),
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"]
        );
        const derivedKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: kdfIterations,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            true, // extractable
            ["encrypt", "decrypt"]
        );

        // Export Private Key (JWK)
        const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

        // Encrypt Private Key
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // AES-GCM recommended IV size
        const encryptedPrivateKey = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            derivedKey,
            new TextEncoder().encode(JSON.stringify(privateKeyJwk))
        );

        // Export Public Key (JWK)
        const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);

        // Construct .nCodeKeys JSON Object
        const nCodeKeysContent = {
            encryptedPrivateKey: arrayBufferToBase64(encryptedPrivateKey),
            publicKey: publicKeyJwk, // publicKeyJwk is already a JSON object
            salt: arrayBufferToBase64(salt),
            iv: arrayBufferToBase64(iv),
            kdfIterations: kdfIterations,
            keyAlgorithm: "RSA-OAEP", // Matches generation
            encryptionAlgorithm: "AES-GCM" // Matches encryption
        };

        // Trigger Download
        downloadFile(JSON.stringify(nCodeKeysContent, null, 2), "encrypted_keys.nCodeKeys", "application/json");

        // Update Global State and UI
        currentKeyPair = keyPair; // Store the actual CryptoKeyPair
        publicKeyDisplayArea.value = JSON.stringify(publicKeyJwk, null, 2);
        copyPublicKeyButton.disabled = false;

        // Clear Passphrase
        keyGenPassphraseInput.value = "";

        alert("Keys generated, encrypted, and download initiated!");

    } catch (error) {
        console.error("Key generation/encryption failed:", error);
        alert("Error generating keys. Check console for details. Ensure you are using a secure context (HTTPS or localhost).");
    }
}

// Helper function to read file as text
function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = (err) => reject(new Error("Failed to read file: " + err.message));
        reader.readAsText(file);
    });
}

// Assumes JSZip library is loaded globally
async function decryptTransmission(event) {
    const dcodeStringOutput = document.getElementById('dcodeStringOutput');
    const dcodeFilesOutput = document.getElementById('dcodeFilesOutput');

    if (!dcodeStringOutput || !dcodeFilesOutput) {
        alert("Required UI elements for decryption output are missing. Please check the page structure.");
        return;
    }

    // Clear previous results
    dcodeStringOutput.value = '';
    dcodeFilesOutput.innerHTML = '';

    if (!currentKeyPair || !currentKeyPair.privateKey) {
        alert("Please load your encrypted key pair first. The private key is needed for decryption.");
        if(event && event.target) event.target.value = null; // Clear file input
        return;
    }

    const file = event.target.files[0];
    if (!file) {
        // This can happen if the user cancels file selection
        // alert("Please select a '.nCodeTransmission' file to decrypt.");
        return;
    }

    if (!file.name.endsWith('.nCodeTransmission')) {
        alert("Invalid file type. Please select a '.nCodeTransmission' file.");
        event.target.value = null; // Clear the file input
        return;
    }

    if (typeof JSZip === 'undefined') {
        alert("JSZip library is not loaded. Decryption cannot proceed.");
        console.error("JSZip is not defined. Please ensure the library is included in your HTML.");
        event.target.value = null;
        return;
    }

    try {
        const fileContent = await readFileAsText(file);
        let transmissionJson;
        try {
            transmissionJson = JSON.parse(fileContent);
        } catch (e) {
            alert("Invalid transmission file format (not valid JSON).");
            console.error("JSON Parsing Error:", e);
            event.target.value = null;
            return;
        }

        const {
            encryptedData: b64EncryptedData,
            encryptedSessionKey: b64EncryptedSessionKey,
            iv: b64Iv,
            transmissionVersion, // Could be used for version-specific handling in future
            sessionKeyParams // Expects { name: "AES-GCM", length: 256 }
        } = transmissionJson;

        if (!b64EncryptedData || !b64EncryptedSessionKey || !b64Iv || !sessionKeyParams) {
            alert("Invalid transmission file content: missing required encrypted data, session key, IV, or session key parameters.");
            event.target.value = null;
            return;
        }
        if (transmissionVersion !== "1.0") {
            alert(`Unsupported transmission version: ${transmissionVersion}. Expected "1.0".`);
            event.target.value = null;
            return;
        }


        const encryptedSessionKey = base64ToArrayBuffer(b64EncryptedSessionKey);
        const iv = base64ToArrayBuffer(b64Iv);
        const encryptedData = base64ToArrayBuffer(b64EncryptedData);

        // Decrypt Session Key
        let decryptedSessionKeyBytes;
        try {
            decryptedSessionKeyBytes = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" }, // No IV for RSA-OAEP itself
                currentKeyPair.privateKey,
                encryptedSessionKey
            );
        } catch (rsaError) {
            console.error("RSA Decryption (Session Key) Error:", rsaError);
            throw new Error("Failed to decrypt session key. This could be due to an incorrect private key or corrupted data.");
        }

        // Import Session Key using params from transmission file
        if (!sessionKeyParams || !sessionKeyParams.name || !sessionKeyParams.length) {
             throw new Error("Session key parameters are missing or invalid in the transmission file.");
        }
        const sessionKey = await window.crypto.subtle.importKey(
            "raw",
            decryptedSessionKeyBytes,
            sessionKeyParams, // e.g., { name: "AES-GCM", length: 256 }
            false, // not extractable
            ["decrypt"]
        );

        // Decrypt Data
        let decryptedZipData;
        try {
            decryptedZipData = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                sessionKey,
                encryptedData
            );
        } catch (aesError) {
            console.error("AES Decryption (Data) Error:", aesError);
            throw new Error("Failed to decrypt data using the session key. The data might be corrupted or the session key decryption failed silently.");
        }


        // Handle Decrypted Output (JSZip)
        const zip = await JSZip.loadAsync(decryptedZipData);
        let foundStringContent = false;
        let fileCount = 0;
        const fileEntries = Object.values(zip.files).filter(file => !file.dir);

        for (const zipEntry of fileEntries) {
            fileCount++;
            // Standardized filename from encryption step
            if (zipEntry.name === "string_content.txt") {
                const stringContent = await zipEntry.async("string");
                dcodeStringOutput.value = stringContent;
                foundStringContent = true;
            } else {
                const fileBlob = await zipEntry.async("blob");
                const link = document.createElement("a");
                link.href = URL.createObjectURL(fileBlob);
                link.textContent = `Download ${zipEntry.name}`;
                link.download = zipEntry.name;
                link.style.display = "block"; // Make each link a block element for better spacing
                link.style.marginBottom = "5px";
                dcodeFilesOutput.appendChild(link);
            }
        }

        if (fileCount === 0 && !foundStringContent) {
             dcodeStringOutput.value = "(No text content or files found in the decrypted transmission)";
        } else if (fileCount > 0) { // Offer download all if there were any files (even if string_content.txt was also there)
            const downloadAllButton = document.createElement("button");
            downloadAllButton.textContent = "Download All Decrypted Files as .zip";
            downloadAllButton.style.marginTop = "10px";
            downloadAllButton.onclick = () => {
                // We already have the decryptedZipData, which is the zip itself
                downloadFile(new Blob([decryptedZipData]), "decrypted_files.zip", "application/zip");
            };
            dcodeFilesOutput.appendChild(downloadAllButton);
        }

        alert("Decryption successful!");
        if(event && event.target) event.target.value = null; // Clear file input

    } catch (error) {
        console.error("Decryption failed:", error);
        let userMessage = "Decryption failed. Check console for details.";
        if (error.message.includes("Failed to decrypt session key") || error.message.includes("Failed to decrypt data")) {
            userMessage = "Decryption failed. This may be due to an incorrect key pair loaded, a corrupted file, or if the file was not encrypted for the loaded key pair.";
        } else if (error.message.includes("Session key parameters") || error.message.includes("Invalid transmission file format") || error.message.includes("Invalid transmission file content")) {
            userMessage = error.message; // More specific error from our checks
        }

        alert(userMessage);
        dcodeStringOutput.value = ''; // Clear output on error
        dcodeFilesOutput.innerHTML = ''; // Clear output on error
        if(event && event.target) event.target.value = null; // Clear file input
    }
}

// Assumes JSZip library is loaded globally (e.g., via a script tag in HTML)
async function encryptTransmission() {
    const recipientPublicKeyInput = document.getElementById('recipientPublicKeyInput');
    const ncodeStringInput = document.getElementById('ncodeStringInput');
    const ncodeFileInput = document.getElementById('ncodeFileInput');

    if (!recipientPublicKeyInput || !ncodeStringInput || !ncodeFileInput) {
        alert("One or more UI elements for encryption are missing. Please check the page setup.");
        return;
    }

    const recipientPublicKeyJwkString = recipientPublicKeyInput.value;
    const stringToEncrypt = ncodeStringInput.value;
    const fileToEncrypt = ncodeFileInput.files[0];

    if (!recipientPublicKeyJwkString) {
        alert("Recipient's public key is required to encrypt the transmission.");
        return;
    }

    if (!stringToEncrypt && !fileToEncrypt) {
        alert("Please provide either a string or select a file to encrypt.");
        return;
    }

    // Check if JSZip is available
    if (typeof JSZip === 'undefined') {
        alert("JSZip library is not loaded. Encryption cannot proceed.");
        console.error("JSZip is not defined. Please ensure the library is included in your HTML.");
        return;
    }


    try {
        let recipientPublicKey;
        try {
            const recipientPublicKeyJwk = JSON.parse(recipientPublicKeyJwkString);
            // Basic validation of JWK before import attempt
            if (!recipientPublicKeyJwk || typeof recipientPublicKeyJwk.kty !== 'string') {
                throw new Error("Invalid JWK structure: missing key type or essential fields.");
            }
            recipientPublicKey = await window.crypto.subtle.importKey(
                "jwk",
                recipientPublicKeyJwk,
                { name: "RSA-OAEP", hash: "SHA-256" }, // Ensure hash matches what was used for key generation
                true, // Not strictly needed to be extractable for encryption
                ["encrypt"]
            );
        } catch (e) {
            alert("Invalid recipient public key format or content. Please ensure it's a valid JWK. Error: " + e.message);
            console.error("Recipient Public Key Import Error:", e);
            return;
        }

        // Generate AES-GCM Session Key
        const sessionKey = await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true, // extractable (to be wrapped)
            ["encrypt", "decrypt"] // "decrypt" usage is not strictly needed for the session key here
        );

        const zip = new JSZip();
        let operations = [];

        if (stringToEncrypt) {
            zip.file("string_content.txt", stringToEncrypt); // Standardized filename
        }

        if (fileToEncrypt) {
            operations.push(new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = (e) => {
                    zip.file(fileToEncrypt.name, e.target.result);
                    resolve();
                };
                reader.onerror = (err) => {
                    console.error("File reading error:", err);
                    reject(new Error("Error reading file: " + fileToEncrypt.name));
                };
                reader.readAsArrayBuffer(fileToEncrypt);
            }));
        }

        await Promise.all(operations); // Wait for file reading if any

        const dataToEncrypt = await zip.generateAsync({
            type: "arraybuffer",
            compression: "DEFLATE",
            compressionOptions: { level: 9 }
        });

        // Encrypt Data (the zipped ArrayBuffer)
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // For AES-GCM data encryption
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            sessionKey,
            dataToEncrypt
        );

        // Export and Encrypt Session Key (as JWK, then encrypt the JWK string)
        // const sessionKeyJwk = await window.crypto.subtle.exportKey("jwk", sessionKey);
        // The raw key bytes are usually preferred for wrapping, not the JWK itself, to minimize size.
        // However, JWK is easier if you need to re-import it with full metadata elsewhere.
        // For wrapping, typically you export as "raw" if the wrapping algorithm supports it,
        // or wrap the JWK string if you need to preserve JWK metadata.
        // RSA-OAEP encrypts an ArrayBuffer. So, we'll encrypt the session key exported as raw bytes.
        // For simplicity and to match potential decryption expecting JWK: export as JWK, then encrypt stringified JWK.
        const sessionKeyExported = await window.crypto.subtle.exportKey("raw", sessionKey); // Export raw key for wrapping

        const encryptedSessionKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" }, // No IV needed for RSA-OAEP itself
            recipientPublicKey,
            sessionKeyExported // Encrypt the raw session key bytes
        );


        // Construct .nCodeTransmission JSON
        const transmissionJson = {
            encryptedData: arrayBufferToBase64(encryptedData),
            encryptedSessionKey: arrayBufferToBase64(encryptedSessionKey), // This is the wrapped raw session key
            iv: arrayBufferToBase64(iv), // IV for the AES-GCM data encryption
            transmissionVersion: "1.0",
            // Optional: add metadata about the session key if not using JWK for it
            // e.g., sessionKeyAlgorithm: "AES-GCM", sessionKeyLength: 256
            // If sessionKeyJwk was encrypted, this wouldn't be needed.
            // Since raw key was encrypted, receiver needs to know how to import it:
            sessionKeyParams: { name: "AES-GCM", length: 256 }
        };

        downloadFile(JSON.stringify(transmissionJson, null, 2), "encrypted_transmission.nCodeTransmission", "application/json");

        alert("Transmission encrypted and download initiated!");
        if (ncodeStringInput) ncodeStringInput.value = '';
        if (ncodeFileInput) ncodeFileInput.value = null;
        // Consider not clearing recipientPublicKeyInput if user wants to send multiple files to same recipient
        // if (recipientPublicKeyInput) recipientPublicKeyInput.value = '';

    } catch (error) {
        console.error("Encryption failed:", error);
        alert(`Encryption failed: ${error.message}. Check console for details.`);
    }
}

function handleUploadEncryptedKeys(event) {
    const file = event.target.files[0];
    if (!file) {
        // No file selected, or deselected
        return;
    }

    if (!file.name.endsWith('.nCodeKeys')) {
        alert("Please select a valid '.nCodeKeys' file.");
        event.target.value = null; // Clear the file input
        uploadedKeyFileData = null;
        return;
    }

    const reader = new FileReader();

    reader.onload = function(e) {
        try {
            const fileContent = e.target.result;
            uploadedKeyFileData = JSON.parse(fileContent);

            // Basic validation of the parsed content
            if (!uploadedKeyFileData || typeof uploadedKeyFileData.encryptedPrivateKey !== 'string' ||
                typeof uploadedKeyFileData.publicKey !== 'object' || typeof uploadedKeyFileData.salt !== 'string' ||
                typeof uploadedKeyFileData.iv !== 'string' || typeof uploadedKeyFileData.kdfIterations !== 'number') {
                alert("The key file is not in the expected format or is missing required fields.");
                uploadedKeyFileData = null;
                event.target.value = null; // Clear the file input
                return;
            }

            alert("Encrypted key file loaded. Please enter your passphrase and click 'Load & Decrypt Keys'.");
            // Optionally, enable the 'Load & Decrypt Keys' button here if it was disabled
            // document.getElementById('decrypt-and-load-keys-button').disabled = false;
        } catch (error) {
            console.error("Error parsing key file:", error);
            alert("Failed to parse the key file. It might be corrupted or not a valid JSON format.");
            uploadedKeyFileData = null;
            event.target.value = null; // Clear the file input
        }
    };

    reader.onerror = function() {
        console.error("Error reading file:", reader.error);
        alert("An error occurred while reading the file.");
        uploadedKeyFileData = null;
        event.target.value = null; // Clear the file input
    };

    reader.readAsText(file);
}

async function loadEncryptedKeys() {
    const keyLoadPassphraseInput = document.getElementById('keyLoadPassphraseInput');
    const publicKeyDisplayArea = document.getElementById('public-key-display-area'); // Corrected ID
    const copyPublicKeyButton = document.getElementById('copyPublicKeyButton');

    if (!keyLoadPassphraseInput || !publicKeyDisplayArea || !copyPublicKeyButton) {
        alert("Required UI elements for key loading are missing.");
        return;
    }

    const passphrase = keyLoadPassphraseInput.value;
    if (!passphrase) {
        alert("Please enter a passphrase to decrypt the keys.");
        return;
    }

    if (!uploadedKeyFileData) {
        alert("No key file loaded. Please upload a '.nCodeKeys' file first using the 'Upload Encrypted Key Pair' button.");
        return;
    }

    try {
        const {
            encryptedPrivateKey: b64EncryptedPrivateKey,
            publicKey: publicKeyJwk,
            salt: b64Salt,
            iv: b64Iv,
            kdfIterations,
            keyAlgorithm,
            encryptionAlgorithm
        } = uploadedKeyFileData;

        // Validate that all necessary fields were present in the uploaded file
        if (!b64EncryptedPrivateKey || !publicKeyJwk || !b64Salt || !b64Iv || kdfIterations === undefined || !keyAlgorithm || !encryptionAlgorithm) {
            throw new Error("Invalid key file format: one or more required fields are missing.");
        }

        if (keyAlgorithm !== "RSA-OAEP" || encryptionAlgorithm !== "AES-GCM") {
            throw new Error(`Unsupported key or encryption algorithm in key file. Expected RSA-OAEP and AES-GCM, got ${keyAlgorithm} and ${encryptionAlgorithm}.`);
        }

        const salt = base64ToArrayBuffer(b64Salt);
        const iv = base64ToArrayBuffer(b64Iv);
        const encryptedPrivateKey = base64ToArrayBuffer(b64EncryptedPrivateKey);

        // Derive Symmetric Key (PBKDF2)
        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(passphrase),
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"]
        );
        const derivedKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: kdfIterations,
                hash: "SHA-256" // Must match the hash used during key generation
            },
            baseKey,
            { name: "AES-GCM", length: 256 }, // Must match the encryption algorithm details
            false, // extractable is false, as we only need it for this decryption operation
            ["decrypt"]
        );

        // Decrypt Private Key
        let decryptedPrivateKeyJwkString;
        try {
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                derivedKey,
                encryptedPrivateKey
            );
            decryptedPrivateKeyJwkString = new TextDecoder().decode(decryptedBuffer);
        } catch (decryptionError) {
            // This is often where a wrong passphrase error will manifest
            console.error("Decryption failed, likely incorrect passphrase:", decryptionError);
            throw new Error("Failed to decrypt keys. Incorrect passphrase or corrupted file.");
        }

        const privateKeyJwk = JSON.parse(decryptedPrivateKeyJwkString);

        // Import Private Key
        const importedPrivateKey = await window.crypto.subtle.importKey(
            "jwk",
            privateKeyJwk,
            { name: "RSA-OAEP", hash: "SHA-256" }, // Must match public key's algorithm and hash
            true, // extractable (for potential future use, though not strictly necessary if only decrypting)
            ["decrypt"]
        );

        // Import Public Key
        const importedPublicKey = await window.crypto.subtle.importKey(
            "jwk",
            publicKeyJwk, // This is directly from the .nCodeKeys file
            { name: "RSA-OAEP", hash: "SHA-256" }, // Must match private key's algorithm and hash
            true, // extractable
            ["encrypt"]
        );

        // Store KeyPair and Update UI
        currentKeyPair = { privateKey: importedPrivateKey, publicKey: importedPublicKey };
        publicKeyDisplayArea.value = JSON.stringify(publicKeyJwk, null, 2);
        copyPublicKeyButton.disabled = false;
        keyLoadPassphraseInput.value = ""; // Clear passphrase

        alert("Keys successfully loaded and decrypted!");

    } catch (error) {
        console.error("Key loading/decryption failed:", error);
        if (error.message.includes("Failed to decrypt keys") || (error.name === 'OperationError' && error.message.toLowerCase().includes("decrypt"))) {
             alert("Failed to decrypt keys. This is often due to an incorrect passphrase or a corrupted/modified key file.");
        } else if (error.message.includes("Invalid key file format")) {
            alert(error.message);
        }
        else {
            alert("Error loading keys. The file may be corrupted, invalid, or algorithms may not match. Check console for details.");
        }
        currentKeyPair = null;
        publicKeyDisplayArea.value = "";
        copyPublicKeyButton.disabled = true;
        // Do not clear uploadedKeyFileData here, user might want to retry with a different passphrase
    }
}

function clearLoadedKeys() {
    const publicKeyDisplayArea = document.getElementById('public-key-display-area');
    const copyPublicKeyButton = document.getElementById('copyPublicKeyButton');
    const keyGenPassphraseInput = document.getElementById('keyGenPassphraseInput');
    const keyLoadPassphraseInput = document.getElementById('keyLoadPassphraseInput');
    const uploadEncryptedKeysInput = document.getElementById('uploadEncryptedKeysInput'); // Assuming this is the ID of the file input for uploading keys

    // Reset global variables
    currentKeyPair = null;
    uploadedKeyFileData = null;

    // Clear UI Elements
    if (publicKeyDisplayArea) {
        publicKeyDisplayArea.value = "";
    }
    if (keyGenPassphraseInput) {
        keyGenPassphraseInput.value = "";
    }
    if (keyLoadPassphraseInput) {
        keyLoadPassphraseInput.value = "";
    }

    // Disable Buttons
    if (copyPublicKeyButton) {
        copyPublicKeyButton.disabled = true;
    }

    // Clear File Input
    if (uploadEncryptedKeysInput) {
        uploadEncryptedKeysInput.value = null; // This effectively clears the selected file
    }

    // User Feedback (Optional but good)
    // Consider if an alert is too intrusive for a clear action.
    // A more subtle notification might be better, or none if the UI changes are obvious.
    // For now, per plan:
    alert("Loaded keys and related data have been cleared.");
}

async function copyPublicKey() {
    const publicKeyDisplayArea = document.getElementById('public-key-display-area');
    const copyButton = document.getElementById('copyPublicKeyButton'); // Assuming this is the button that triggers the copy

    if (!publicKeyDisplayArea) {
        console.error("Public key display area not found.");
        alert("Cannot copy public key: display area missing.");
        return;
    }

    const publicKeyText = publicKeyDisplayArea.value;

    if (!publicKeyText) {
        alert("No public key available to copy. Generate or load keys first.");
        return;
    }

    if (!navigator.clipboard || !navigator.clipboard.writeText) {
        alert("Clipboard API not available. This might be due to an insecure context (HTTP) or browser limitations.");
        console.warn("navigator.clipboard.writeText is not available.");
        // Fallback for older browsers or insecure contexts (less ideal)
        try {
            publicKeyDisplayArea.select(); // Select the text
            document.execCommand('copy'); // Attempt to copy
            publicKeyDisplayArea.setSelectionRange(0, 0); // Deselect
            alert("Public key selected. Press Ctrl+C or Cmd+C to copy.");
        } catch (err) {
            console.error("Fallback copy method failed:", err);
            alert("Failed to copy public key using fallback. Please copy manually.");
        }
        return;
    }

    try {
        await navigator.clipboard.writeText(publicKeyText);
        alert("Public key copied to clipboard!");

        if (copyButton) {
            const originalButtonText = copyButton.textContent;
            copyButton.textContent = "Copied!";
            setTimeout(() => {
                copyButton.textContent = originalButtonText;
            }, 2000);
        }

    } catch (error) {
        console.error("Failed to copy public key using Clipboard API:", error);
        alert("Failed to copy public key. This can sometimes happen if the page doesn't have focus or due to browser security settings. See console for details.");
    }
}


document.addEventListener('DOMContentLoaded', function () {
    const modeToggle = document.getElementById('transmission-mode-toggle');
    const ncodeSection = document.getElementById('ncode-section');
    const dcodeSection = document.getElementById('dcode-section');

    if (modeToggle && ncodeSection && dcodeSection) {
        modeToggle.addEventListener('change', function() {
            if (this.checked) { // DCode mode
                ncodeSection.style.display = 'none';
                dcodeSection.style.display = 'block';
            } else { // NCode mode
                ncodeSection.style.display = 'block';
                dcodeSection.style.display = 'none';
            }
        });

        // Set initial state based on checkbox default (optional, but good practice)
        // Assuming NCode is default (checkbox is unchecked)
        // HTML already has dcode-section hidden by default, so this matches.
        if (modeToggle.checked) {
            ncodeSection.style.display = 'none';
            dcodeSection.style.display = 'block';
        } else {
            ncodeSection.style.display = 'block';
            dcodeSection.style.display = 'none';
        }
    } else {
        console.error('Transmission mode toggle elements not found!');
    }

    // (Assuming this is appended inside the existing DOMContentLoaded listener)

    const clearLoadedKeysButton = document.getElementById('clear-loaded-keys-button');
    const publicKeyDisplayArea = document.getElementById('public-key-display-area');
    const uploadKeyPairInput = document.getElementById('upload-key-pair-input');
    const decryptKeyPassphraseInput = document.getElementById('decrypt-key-passphrase');

    if (clearLoadedKeysButton && publicKeyDisplayArea && uploadKeyPairInput && decryptKeyPassphraseInput) {
        clearLoadedKeysButton.addEventListener('click', function() {
            publicKeyDisplayArea.value = ''; // Clear textarea
            uploadKeyPairInput.value = ''; // Clear file input
            decryptKeyPassphraseInput.value = ''; // Clear password input
        });
    } else {
        console.error('Clear loaded keys button or associated elements not found!');
    }
});
