let currentKeyPair = null;
let uploadedKeyFileData = null;

function showToast(message, duration = 5000) {
    const container = document.getElementById('toast-container');
    if (!container) {
        console.error('Toast container not found!');
        // Fallback to alert if container is missing, though it shouldn't be
        alert(message);
        return;
    }

    const toast = document.createElement('div');
    toast.className = 'toast-message'; // Apply CSS class
    toast.textContent = message;

    container.appendChild(toast);

    // Automatically remove the toast after 'duration'
    setTimeout(() => {
        toast.style.opacity = '0'; // Start fade out
        setTimeout(() => { // Wait for fade out to complete
            if (toast.parentNode === container) { // Check if still child before removing
                container.removeChild(toast);
            }
        }, 500); // Match opacity transition time
    }, duration);
}

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
        showToast("Required UI elements for key generation are missing. Please check the page structure.");
        return;
    }

    const passphrase = keyGenPassphraseInput.value;
    if (!passphrase) {
        showToast("Please enter a passphrase to encrypt the keys.");
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

        showToast("Keys generated, encrypted, and download initiated!");

    } catch (error) {
        console.error("Key generation/encryption failed:", error);
        showToast("Error generating keys. Check console for details. Ensure you are using a secure context (HTTPS or localhost).");
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
    const awaitingMessage = document.getElementById('awaiting-decryption-message');

    // Clear previous results and show awaiting message
    if (dcodeStringOutput) dcodeStringOutput.value = '';
    if (dcodeFilesOutput) dcodeFilesOutput.innerHTML = '';
    if (awaitingMessage) awaitingMessage.style.display = 'block'; // Or 'inline' or other default

    if (!dcodeStringOutput || !dcodeFilesOutput) { // awaitingMessage can be optional
        showToast("Required UI elements for decryption output are missing. Please check the page structure.");
        if (awaitingMessage) awaitingMessage.style.display = 'none'; // Hide if critical elements missing
        return;
    }

    if (!currentKeyPair || !currentKeyPair.privateKey) {
        showToast("Please load your encrypted key pair first. The private key is needed for decryption.");
        if(event && event.target) event.target.value = null; // Clear file input
        return;
    }

    const file = event.target.files[0];
    if (!file) {
        // This can happen if the user cancels file selection
        // alert("Please select a '.nCodeTransmission' file to decrypt.");
        return;
    }

    if (!(file.name.endsWith('.nCodeTransmission') || file.name.endsWith('.json'))) {
        showToast("Invalid file type. Please select a '.nCodeTransmission' or '.json' file.");
        event.target.value = null; // Clear the file input
        return;
    }

    if (typeof JSZip === 'undefined') {
        showToast("JSZip library is not loaded. Decryption cannot proceed.");
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
            showToast("Invalid transmission file format (not valid JSON).");
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
            showToast("Invalid transmission file content: missing required encrypted data, session key, IV, or session key parameters.");
            event.target.value = null;
            return;
        }
        if (transmissionVersion !== "1.0") {
            showToast(`Unsupported transmission version: ${transmissionVersion}. Expected "1.0".`);
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
                // Apply new styling for links
                link.className = "inline-block bg-[#5bc0de] text-[#131811] px-3 py-2 rounded text-sm font-bold leading-normal tracking-[0.015em] hover:bg-[#46b8da] focus:outline-none focus:ring-2 focus:ring-[#5bc0de] focus:ring-opacity-50 cursor-pointer no-underline";
                link.style.marginRight = "5px";
                link.style.marginBottom = "5px";
                dcodeFilesOutput.appendChild(link);
            }
        }

        if (awaitingMessage) awaitingMessage.style.display = 'none'; // Hide after processing files

        if (fileCount === 0 && !foundStringContent) {
             dcodeStringOutput.value = "(No text content or files found in the decrypted transmission)";
             if (awaitingMessage) awaitingMessage.style.display = 'block'; // Show if nothing found
        } else if (fileCount > 0) {
            const downloadAllButton = document.createElement("button");
            downloadAllButton.textContent = "Download All Decrypted Files as .zip";
            // Apply new styling for the button
            downloadAllButton.className = "inline-block bg-[#47c10a] text-[#131811] px-3 py-2 rounded text-sm font-bold leading-normal tracking-[0.015em] hover:bg-[#3aa107] focus:outline-none focus:ring-2 focus:ring-[#47c10a] focus:ring-opacity-50 cursor-pointer";
            downloadAllButton.style.marginTop = "10px";
            downloadAllButton.onclick = () => {
                downloadFile(new Blob([decryptedZipData]), "decrypted_files.zip", "application/zip");
            };
            dcodeFilesOutput.appendChild(downloadAllButton);
        }

        showToast("Decryption successful!");
        if(event && event.target) event.target.value = null; // Clear file input

    } catch (error) {
        console.error("Decryption failed:", error);
        let userMessage = "Decryption failed. Check console for details.";
        if (error.message.includes("Failed to decrypt session key") || error.message.includes("Failed to decrypt data")) {
            userMessage = "Decryption failed. This may be due to an incorrect key pair loaded, a corrupted file, or if the file was not encrypted for the loaded key pair.";
        } else if (error.message.includes("Session key parameters") || error.message.includes("Invalid transmission file format") || error.message.includes("Invalid transmission file content")) {
            userMessage = error.message; // More specific error from our checks
        }

        showToast(userMessage);
        // Clear outputs and show awaiting message on error
        if (dcodeStringOutput) dcodeStringOutput.value = '';
        if (dcodeFilesOutput) dcodeFilesOutput.innerHTML = '';
        if (awaitingMessage) awaitingMessage.style.display = 'block'; // Or 'inline'

        if(event && event.target) event.target.value = null; // Clear file input
    }
}

// Assumes JSZip library is loaded globally (e.g., via a script tag in HTML)
async function encryptTransmission() {
    const recipientPublicKeyInput = document.getElementById('recipientPublicKeyInput');
    const ncodeStringInput = document.getElementById('ncodeStringInput');
    const ncodeFileInput = document.getElementById('ncodeFileInput');

    if (!recipientPublicKeyInput || !ncodeStringInput || !ncodeFileInput) {
        showToast("One or more UI elements for encryption are missing. Please check the page setup.");
        return;
    }

    const recipientPublicKeyJwkString = recipientPublicKeyInput.value;
    const stringToEncrypt = ncodeStringInput.value;
    const fileToEncrypt = ncodeFileInput.files[0];

    if (!recipientPublicKeyJwkString) {
        showToast("Recipient's public key is required to encrypt the transmission.");
        return;
    }

    if (!stringToEncrypt && !fileToEncrypt) {
        showToast("Please provide either a string or select a file to encrypt.");
        return;
    }

    // Check if JSZip is available
    if (typeof JSZip === 'undefined') {
        showToast("JSZip library is not loaded. Encryption cannot proceed.");
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
            showToast("Invalid recipient public key format or content. Please ensure it's a valid JWK. Error: " + e.message);
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

        showToast("Transmission encrypted and download initiated!");
        if (ncodeStringInput) ncodeStringInput.value = '';
        if (ncodeFileInput) ncodeFileInput.value = null;
        // Consider not clearing recipientPublicKeyInput if user wants to send multiple files to same recipient
        // if (recipientPublicKeyInput) recipientPublicKeyInput.value = '';

    } catch (error) {
        console.error("Encryption failed:", error);
        showToast(`Encryption failed: ${error.message}. Check console for details.`);
    }
}

function handleUploadEncryptedKeys(event) {
    const file = event.target.files[0];
    if (!file) {
        // No file selected, or deselected
        return;
    }

    if (!(file.name.endsWith('.nCodeKeys') || file.name.endsWith('.json'))) {
        showToast("Please select a valid '.nCodeKeys' or '.json' file.");
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
                showToast("The key file is not in the expected format or is missing required fields.");
                uploadedKeyFileData = null;
                event.target.value = null; // Clear the file input
                return;
            }

            showToast("Encrypted key file loaded. Please enter your passphrase and click 'Load & Decrypt Keys'.");
            // Optionally, enable the 'Load & Decrypt Keys' button here if it was disabled
            // document.getElementById('decrypt-and-load-keys-button').disabled = false;
        } catch (error) {
            console.error("Error parsing key file:", error);
            showToast("Failed to parse the key file. It might be corrupted or not a valid JSON format.");
            uploadedKeyFileData = null;
            event.target.value = null; // Clear the file input
        }
    };

    reader.onerror = function() {
        console.error("Error reading file:", reader.error);
        showToast("An error occurred while reading the file.");
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
        showToast("Required UI elements for key loading are missing.");
        return;
    }

    const passphrase = keyLoadPassphraseInput.value;
    if (!passphrase) {
        showToast("Please enter a passphrase to decrypt the keys.");
        return;
    }

    if (!uploadedKeyFileData) {
        showToast("No key file loaded. Please upload a '.nCodeKeys' file first using the 'Upload Encrypted Key Pair' button.");
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

        showToast("Keys successfully loaded and decrypted!");

    } catch (error) {
        console.error("Key loading/decryption failed:", error);
        if (error.message.includes("Failed to decrypt keys") || (error.name === 'OperationError' && error.message.toLowerCase().includes("decrypt"))) {
             showToast("Failed to decrypt keys. This is often due to an incorrect passphrase or a corrupted/modified key file.");
        } else if (error.message.includes("Invalid key file format")) {
            showToast(error.message);
        }
        else {
            showToast("Error loading keys. The file may be corrupted, invalid, or algorithms may not match. Check console for details.");
        }
        currentKeyPair = null;
        publicKeyDisplayArea.value = "";
        copyPublicKeyButton.disabled = true;
        // Do not clear uploadedKeyFileData here, user might want to retry with a different passphrase
    }
}

function clearLoadedKeys() {
    // Reset global variables
    currentKeyPair = null;
    uploadedKeyFileData = null;

    // Clear UI Elements
    // Key Management Section related
    const keyGenPassphraseInput = document.getElementById('keyGenPassphraseInput');
    if (keyGenPassphraseInput) keyGenPassphraseInput.value = "";

    const keyLoadPassphraseInput = document.getElementById('keyLoadPassphraseInput');
    if (keyLoadPassphraseInput) keyLoadPassphraseInput.value = "";

    const uploadEncryptedKeysInput = document.getElementById('uploadEncryptedKeysInput');
    if (uploadEncryptedKeysInput) uploadEncryptedKeysInput.value = null; // Clears file selection

    const publicKeyDisplayArea = document.getElementById('public-key-display-area');
    if (publicKeyDisplayArea) publicKeyDisplayArea.value = "";

    const copyPublicKeyButton = document.getElementById('copyPublicKeyButton');
    if (copyPublicKeyButton) copyPublicKeyButton.disabled = true; // Also disable copy button

    // nCode Workflow Section related
    const recipientPublicKeyInput = document.getElementById('recipientPublicKeyInput');
    if (recipientPublicKeyInput) recipientPublicKeyInput.value = "";

    const ncodeFileInput = document.getElementById('ncodeFileInput');
    if (ncodeFileInput) ncodeFileInput.value = null; // Clears file selection

    const ncodeStringInput = document.getElementById('ncodeStringInput');
    if (ncodeStringInput) ncodeStringInput.value = "";

    // dCode Workflow Section related
    const dcodeFileInput = document.getElementById('dcodeFileInput');
    if (dcodeFileInput) dcodeFileInput.value = null; // Clears file selection

    const dcodeStringOutput = document.getElementById('dcodeStringOutput');
    if (dcodeStringOutput) dcodeStringOutput.value = "";

    const dcodeFilesOutput = document.getElementById('dcodeFilesOutput');
    if (dcodeFilesOutput) dcodeFilesOutput.innerHTML = ""; // Clear any generated links or messages

    // No alert needed as per new requirements.
    // console.log("Loaded keys and related data have been cleared."); // Optional: for debugging
}

async function copyPublicKey() {
    const publicKeyDisplayArea = document.getElementById('public-key-display-area');
    const copyButton = document.getElementById('copyPublicKeyButton'); // Assuming this is the button that triggers the copy

    if (!publicKeyDisplayArea) {
        console.error("Public key display area not found.");
        showToast("Cannot copy public key: display area missing.");
        return;
    }

    const publicKeyText = publicKeyDisplayArea.value;

    if (!publicKeyText) {
        showToast("No public key available to copy. Generate or load keys first.");
        return;
    }

    if (!navigator.clipboard || !navigator.clipboard.writeText) {
        showToast("Clipboard API not available. This might be due to an insecure context (HTTP) or browser limitations.");
        console.warn("navigator.clipboard.writeText is not available.");
        // Fallback for older browsers or insecure contexts (less ideal)
        try {
            publicKeyDisplayArea.select(); // Select the text
            document.execCommand('copy'); // Attempt to copy
            publicKeyDisplayArea.setSelectionRange(0, 0); // Deselect
            showToast("Public key selected. Press Ctrl+C or Cmd+C to copy.");
        } catch (err) {
            console.error("Fallback copy method failed:", err);
            showToast("Failed to copy public key using fallback. Please copy manually.");
        }
        return;
    }

    try {
        await navigator.clipboard.writeText(publicKeyText);
        showToast("Public key copied to clipboard!");

        if (copyButton) {
            const originalButtonText = copyButton.textContent;
            copyButton.textContent = "Copied!";
            setTimeout(() => {
                copyButton.textContent = originalButtonText;
            }, 2000);
        }

    } catch (error) {
        console.error("Failed to copy public key using Clipboard API:", error);
        showToast("Failed to copy public key. This can sometimes happen if the page doesn't have focus or due to browser security settings. See console for details.");
    }
}


document.addEventListener('DOMContentLoaded', function () {
    // Mode toggle logic
    const modeToggle = document.getElementById('transmission-mode-toggle');
    const ncodeSection = document.getElementById('ncode-section');
    const dcodeSection = document.getElementById('dcode-section');
    const keyPairManagementSection = document.getElementById('key-pair-management-section');
    const keyGenerationGroupContainer = document.getElementById('key-generation-group-container'); // Changed

    if (modeToggle && ncodeSection && dcodeSection && keyPairManagementSection && keyGenerationGroupContainer) { // Changed
        function updateDisplayMode() {
            keyPairManagementSection.style.display = 'block'; // Ensure parent section is always visible

            if (modeToggle.checked) { // DCode mode selected
                ncodeSection.style.display = 'none';
                dcodeSection.style.display = 'block';
                keyGenerationGroupContainer.style.display = 'none'; // Changed
            } else { // NCode mode selected
                ncodeSection.style.display = 'block';
                dcodeSection.style.display = 'none';
                keyGenerationGroupContainer.style.display = 'block'; // Changed
            }
        }

        modeToggle.addEventListener('change', updateDisplayMode);
        // Set initial state
        updateDisplayMode();
    } else {
        console.error('One or more transmission mode toggle elements or sections not found! Check IDs: transmission-mode-toggle, ncode-section, dcode-section, key-pair-management-section, key-generation-group-container'); // Changed
    }

    // Get DOM elements for nCode/dCode Key Management and Workflows
    const generateAndDownloadKeysButton = document.getElementById('generateAndDownloadKeysButton');
    const uploadEncryptedKeysInput = document.getElementById('uploadEncryptedKeysInput');
    const loadKeysButton = document.getElementById('loadKeysButton');
    const clearKeysButton = document.getElementById('clearKeysButton'); // This is the new ID
    const copyPublicKeyButton = document.getElementById('copyPublicKeyButton');

    const encryptAndDownloadButton = document.getElementById('encryptAndDownloadButton');
    const dcodeFileInput = document.getElementById('dcodeFileInput');

    // Attach event listeners for Key Gen & Management
    if (generateAndDownloadKeysButton) {
        generateAndDownloadKeysButton.addEventListener('click', generateAndEncryptKeys);
    } else {
        console.error('generateAndDownloadKeysButton not found');
    }

    if (uploadEncryptedKeysInput) {
        uploadEncryptedKeysInput.addEventListener('change', handleUploadEncryptedKeys);
    } else {
        console.error('uploadEncryptedKeysInput not found');
    }

    if (loadKeysButton) {
        loadKeysButton.addEventListener('click', loadEncryptedKeys);
    } else {
        console.error('loadKeysButton not found');
    }

    if (clearKeysButton) { // Using the new ID
        clearKeysButton.addEventListener('click', clearLoadedKeys);
    } else {
        console.error('clearKeysButton not found');
    }

    if (copyPublicKeyButton) {
        copyPublicKeyButton.addEventListener('click', copyPublicKey);
    } else {
        console.error('copyPublicKeyButton not found');
    }

    // Attach event listeners for NCode (Encryption)
    if (encryptAndDownloadButton) {
        encryptAndDownloadButton.addEventListener('click', encryptTransmission);
    } else {
        console.error('encryptAndDownloadButton not found');
    }

    // Attach event listeners for DCode (Decryption)
    if (dcodeFileInput) {
        dcodeFileInput.addEventListener('change', decryptTransmission);
    } else {
        console.error('dcodeFileInput not found');
    }

    // Initial UI setup
    // Disable buttons that require keys or specific conditions to be met
    if (copyPublicKeyButton) {
        copyPublicKeyButton.disabled = true; // Disabled until a public key is loaded/generated
    }

    // const publicKeyDisplayArea = document.getElementById('public-key-display-area');
    // const oldClearLoadedKeysButton = document.getElementById('clear-loaded-keys-button'); // Old ID
    // const oldUploadKeyPairInput = document.getElementById('upload-key-pair-input'); // Old ID
    // const oldDecryptKeyPassphraseInput = document.getElementById('decrypt-key-passphrase'); // Old ID

    // The following block was part of the original script.
    // It targets elements by their OLD IDs.
    // Since `clearKeysButton` (new ID) now calls `clearLoadedKeys` which is more comprehensive,
    // this specific listener for 'clear-loaded-keys-button' (old ID) can be removed.
    // If other functionality relied on these old IDs, it would need updating.
    // For now, we assume the new event listeners cover the intended functionality with new IDs.
    /*
    if (oldClearLoadedKeysButton && publicKeyDisplayArea && oldUploadKeyPairInput && oldDecryptKeyPassphraseInput) {
        oldClearLoadedKeysButton.addEventListener('click', function() {
            // This is now handled by clearKeysButton -> clearLoadedKeys()
            // publicKeyDisplayArea.value = '';
            // oldUploadKeyPairInput.value = '';
            // oldDecryptKeyPassphraseInput.value = '';
            console.log("Old clear button listener called - should be removed or updated if clearKeysButton is working.");
        });
    } else {
        // console.error('Old clear loaded keys button or its associated elements not found! This might be okay if new clearKeysButton is used.');
    }
    */
});
