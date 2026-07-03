import init, { encrypt_message, decrypt_message } from "./pkg/EasyEncryptionService.js";

async function run() {
    const wasmUrl = chrome.runtime.getURL("pkg/EasyEncryptionService_bg.wasm");
    const bytes = await fetch(wasmUrl).then(r => r.arrayBuffer());
    await init({ module_or_path: bytes });

    // Pre-fill from a right-click selection, if any
    const { pendingText } = await chrome.storage.local.get("pendingText");
    if (pendingText) {
        document.getElementById("input").value = pendingText;
        chrome.storage.local.remove("pendingText"); // consume it so it doesn't linger for next open
    }

    document.getElementById("analyze").addEventListener("click", () => {
        const text = document.getElementById("input").value;
        const key = document.getElementById("key").value;
        document.getElementById("sentences").textContent = encrypt_message(text, key);
        document.getElementById("results").style.display = "block";
    });

    document.getElementById("decrypt").addEventListener("click", async () => {
        const packed = document.getElementById("input").value;
        const fileInput = document.getElementById("privkey");
        const errorEl = document.getElementById("error");
        errorEl.textContent = "";

        if (!fileInput.files.length) {
            errorEl.textContent = "Select your private_key.pkcs8 file first.";
            return;
        }

        try {
            const buffer = await fileInput.files[0].arrayBuffer();
            const keyBytes = new Uint8Array(buffer);
            const decryptedText = decrypt_message(packed, keyBytes);
            document.getElementById("decrypted").textContent = decryptedText;
            document.getElementById("decryptResults").style.display = "block";
        } catch (err) {
            errorEl.textContent = `Decrypt error: ${err.message || err}`;
        }
    });
}

run();