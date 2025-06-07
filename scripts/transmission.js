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
