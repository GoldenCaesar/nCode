document.addEventListener('DOMContentLoaded', () => {
    const selectFileButton = document.getElementById('selectFileButton');
    const fileInput = document.getElementById('fileInput');
    const fileProgressBar = document.getElementById('fileProgressBar');
    const filePasswordInput = document.getElementById('filePasswordInput');
    const fileProcessButton = document.getElementById('fileProcessButton');
    const fileResultOutput = document.getElementById('fileResultOutput');
    const fileModeToggle = document.getElementById('fileModeToggle'); // true for dCode (decrypt), false for nCode (encrypt)
    const downloadFileButton = document.getElementById('downloadFileButton');
    const clearFileButton = document.getElementById('clearFileButton');

    let selectedFile = null;
    let processedFileParts = []; // Encryption: [{salt}, {iv, data}, ...], Decryption: [ArrayBuffer_chunk, ...]
    let originalFileName = '';
    let processedFileBlob = null; // Stores the final Blob for download

    const CHUNK_SIZE = 1024 * 1024; // 1MB (plaintext chunk size)
    const SALT_LENGTH = 16;
    const IV_LENGTH = 12;
    const TAG_LENGTH = 16; // AES-GCM authentication tag length

    if (selectFileButton) {
        selectFileButton.addEventListener('click', () => {
            if (fileInput) fileInput.click();
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', (event) => {
            selectedFile = event.target.files[0];
            if (selectedFile) {
                originalFileName = selectedFile.name;
                console.log('File selected:', selectedFile.name);
                if (fileResultOutput) fileResultOutput.value = `File selected: ${selectedFile.name}\nSize: ${selectedFile.size} bytes. Ready for processing.`;
                if (fileProgressBar) fileProgressBar.style.width = '0%';
                clearProcessedData(); // Clear previous results
            }
        });
    }

    function clearProcessedData() {
        processedFileParts = [];
        processedFileBlob = null;
        if (downloadFileButton) downloadFileButton.disabled = true;
    }

    async function deriveKeyFromPassword(password, salt) {
        try {
            const enc = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                "raw",
                enc.encode(password),
                { name: "PBKDF2" },
                false,
                ["deriveBits", "deriveKey"]
            );
            return await crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: salt,
                    iterations: 100000,
                    hash: "SHA-256",
                },
                keyMaterial,
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
        } catch (e) {
            console.error("Key derivation error:", e);
            throw new Error("Failed to derive key: " + e.message);
        }
    }

    async function encryptChunk(key, dataChunk, iv) {
        try {
            return await crypto.subtle.encrypt( { name: "AES-GCM", iv: iv }, key, dataChunk );
        } catch (e) {
            console.error("Encryption error:", e);
            throw new Error("Failed to encrypt chunk: " + e.message);
        }
    }

    async function decryptChunk(key, encryptedChunk, iv) {
        try {
            return await crypto.subtle.decrypt( { name: "AES-GCM", iv: iv }, key, encryptedChunk );
        } catch (e) {
            console.error("Decryption error:", e);
            throw new Error("Failed to decrypt chunk. Check password or file integrity. " + e.message);
        }
    }

    function updateProgress(percentage) {
        if (fileProgressBar) fileProgressBar.style.width = percentage + '%';
    }

    // Reads a specific slice of a file as an ArrayBuffer
    async function readFileSlice(file, start, end) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsArrayBuffer(file.slice(start, end));
        });
    }

    async function processFileInChunks(file, password, isDecryptMode) {
        if (!file || !password) {
            if (fileResultOutput) fileResultOutput.value = "File and password are required.";
            return;
        }

        updateProgress(0);
        clearProcessedData();
        const totalFileSize = file.size;
        let operationSuccessful = false;

        try {
            if (fileResultOutput) fileResultOutput.value = `Starting file processing (${isDecryptMode ? 'decrypt' : 'encrypt'})...\n`;

            if (isDecryptMode) {
                // --- DECRYPTION ---
                if (totalFileSize < SALT_LENGTH + IV_LENGTH + TAG_LENGTH) { // Basic check for minimal size
                    throw new Error("File is too short to be a valid encrypted file.");
                }
                if (fileResultOutput) fileResultOutput.value += "Reading salt...\n";
                const salt = await readFileSlice(file, 0, SALT_LENGTH);
                updateProgress(5);

                if (fileResultOutput) fileResultOutput.value += "Deriving key...\n";
                const key = await deriveKeyFromPassword(password, salt);
                updateProgress(10);

                let currentOffset = SALT_LENGTH;
                const decryptedPlaintextChunks = [];

                if (fileResultOutput) fileResultOutput.value += "Decrypting file content...\n";
                while (currentOffset < totalFileSize) {
                    if (currentOffset + IV_LENGTH > totalFileSize) throw new Error("Truncated file: not enough data for IV.");
                    const iv = await readFileSlice(file, currentOffset, currentOffset + IV_LENGTH);
                    currentOffset += IV_LENGTH;

                    const remainingFileSize = totalFileSize - currentOffset;
                    // Determine encrypted data size: CHUNK_SIZE of original plaintext + TAG_LENGTH, or whatever is left for the last chunk.
                    const expectedPlaintextChunkSize = Math.min(CHUNK_SIZE, remainingFileSize - TAG_LENGTH);
                    if (expectedPlaintextChunkSize < 0) throw new Error("Truncated file: not enough data for encrypted content beyond IV.");

                    const encryptedDataLength = expectedPlaintextChunkSize + TAG_LENGTH;
                    if (currentOffset + encryptedDataLength > totalFileSize) throw new Error("Truncated file: not enough data for the current chunk based on expected size.");

                    const encryptedDataWithTag = await readFileSlice(file, currentOffset, currentOffset + encryptedDataLength);
                    currentOffset += encryptedDataLength;

                    const decryptedChunk = await decryptChunk(key, encryptedDataWithTag, iv);
                    decryptedPlaintextChunks.push(decryptedChunk);

                    updateProgress(10 + (currentOffset / totalFileSize) * 85); // Progress from 10% to 95%
                    await new Promise(resolve => setTimeout(resolve, 0)); // Yield
                }
                processedFileParts = decryptedPlaintextChunks; // Store array of ArrayBuffers
                operationSuccessful = true;
                if (fileResultOutput) fileResultOutput.value += "Decryption complete.\n";

            } else {
                // --- ENCRYPTION ---
                if (fileResultOutput) fileResultOutput.value += "Generating salt and deriving key...\n";
                const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
                processedFileParts.push({ salt: salt }); // Store salt as the first part
                const key = await deriveKeyFromPassword(password, salt);
                updateProgress(10); // Key derived

                if (fileResultOutput) fileResultOutput.value += "Encrypting file content...\n";
                let currentOffset = 0;
                let chunksProcessed = 0;
                const totalPlaintextChunks = Math.ceil(totalFileSize / CHUNK_SIZE);

                while (currentOffset < totalFileSize) {
                    const plaintextChunkSize = Math.min(CHUNK_SIZE, totalFileSize - currentOffset);
                    const plaintextChunk = await readFileSlice(file, currentOffset, currentOffset + plaintextChunkSize);
                    currentOffset += plaintextChunkSize;

                    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
                    const encryptedData = await encryptChunk(key, plaintextChunk, iv); // includes tag
                    processedFileParts.push({ iv: iv, data: encryptedData });
                    chunksProcessed++;
                    updateProgress(10 + (chunksProcessed / totalPlaintextChunks) * 85); // Progress from 10% to 95%
                    await new Promise(resolve => setTimeout(resolve, 0)); // Yield
                }
                operationSuccessful = true;
                if (fileResultOutput) fileResultOutput.value += "Encryption complete. Click Download File to save.\n";
            }

            prepareDownloadableBlob(isDecryptMode);
            if (fileResultOutput && isDecryptMode && operationSuccessful) {
                // Try to display decrypted text
                const fullDecryptedBuffer = processedFileParts.reduce((acc, chunk) => {
                    const tmp = new Uint8Array(acc.byteLength + chunk.byteLength);
                    tmp.set(new Uint8Array(acc), 0);
                    tmp.set(new Uint8Array(chunk), acc.byteLength);
                    return tmp.buffer;
                }, new ArrayBuffer(0));

                try {
                    const textDecoder = new TextDecoder('utf-8', { fatal: true });
                    const decryptedText = textDecoder.decode(fullDecryptedBuffer);
                    fileResultOutput.value += `\n--- Decrypted Content ---\n${decryptedText}`;
                } catch (e) {
                    fileResultOutput.value += "\nDecrypted content is binary or not valid UTF-8. Click Download File to save.";
                }
            }
            updateProgress(100);
            if(operationSuccessful) downloadFileButton.disabled = false;

        } catch (error) {
            console.error("File processing error:", error);
            if (fileResultOutput) fileResultOutput.value += `\nError: ${error.message}\nProcessing failed.`;
            updateProgress(0); // Reset on error
            clearProcessedData();
             operationSuccessful = false;
        } finally {
            // Enable/disable buttons
        }
    }

    function prepareDownloadableBlob(isDecryptMode) {
        if (processedFileParts.length === 0) {
            console.warn("No processed parts to prepare blob from.");
            processedFileBlob = null;
            return;
        }

        if (isDecryptMode) {
            // processedFileParts contains ArrayBuffers of decrypted plaintext
            processedFileBlob = new Blob(processedFileParts, { type: 'application/octet-stream' });
        } else { // Encryption mode
            const blobPartsArray = [];
            const saltPart = processedFileParts.find(p => p.salt);
            if (saltPart) {
                blobPartsArray.push(saltPart.salt);
            } else {
                console.error("Salt not found in processed parts for encryption!");
                processedFileBlob = null;
                return; // Cannot create valid encrypted file without salt
            }

            processedFileParts.filter(p => p.iv && p.data).forEach(part => {
                blobPartsArray.push(part.iv);
                blobPartsArray.push(part.data);
            });
            processedFileBlob = new Blob(blobPartsArray, { type: 'application/octet-stream' });
        }
    }


    if (fileProcessButton) {
        fileProcessButton.addEventListener('click', async () => {
            if (!selectedFile) {
                if (fileResultOutput) fileResultOutput.value = 'Please select a file first.';
                return;
            }
            if (!filePasswordInput || !filePasswordInput.value) {
                if (fileResultOutput) fileResultOutput.value = 'Password is required.';
                return;
            }

            fileProcessButton.disabled = true;
            clearFileButton.disabled = true;
            downloadFileButton.disabled = true; // Keep disabled until success

            const password = filePasswordInput.value;
            const isDecryptMode = fileModeToggle.checked;

            await processFileInChunks(selectedFile, password, isDecryptMode);

            fileProcessButton.disabled = false; // Re-enable after process
            clearFileButton.disabled = false;
            // downloadFileButton is enabled by processFileInChunks on success
        });
    }

    if (downloadFileButton) {
        downloadFileButton.addEventListener('click', () => {
            if (!processedFileBlob) {
                if (fileResultOutput) fileResultOutput.value = (fileResultOutput.value ? fileResultOutput.value + "\n" : "") + 'No processed file to download. Please process a file first.';
                console.error('No processedFileBlob to download.');
                return;
            }

            try {
                const isDecryptMode = fileModeToggle.checked;
                let fileNameToDownload;

                if (isDecryptMode) {
                    let name = originalFileName;
                    if (name.toLowerCase().endsWith('.ncde')) {
                        name = name.substring(0, name.length - 5);
                    }
                    if (!name) name = "decrypted_file"; // Default if original was just ".ncde" or empty
                    fileNameToDownload = name;
                } else { // Encrypt mode
                    fileNameToDownload = "nCode_encrypted_" + (originalFileName.replace(/[\s]/g, '_') || "file") + ".ncde";
                }

                const url = URL.createObjectURL(processedFileBlob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileNameToDownload;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                if (fileResultOutput) fileResultOutput.value += '\nDownload initiated.';
            } catch (e) {
                console.error("Download error:", e);
                if (fileResultOutput) fileResultOutput.value += `\nDownload failed: ${e.message}`;
            }
        });
    }

    if (clearFileButton) {
        clearFileButton.addEventListener('click', () => {
            selectedFile = null;
            originalFileName = '';
            if (fileInput) fileInput.value = ''; // Clear the file input selection
            if (filePasswordInput) filePasswordInput.value = '';
            if (fileResultOutput) fileResultOutput.value = '';
            updateProgress(0);
            clearProcessedData(); // Clears parts, blob, and disables download button
            console.log('File selection, fields, and processed data cleared.');
        });
    }
});
