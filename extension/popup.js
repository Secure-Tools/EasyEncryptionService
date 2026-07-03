import init, { encrypt_message, decrypt_message } from "./pkg/EasyEncryptionService.js";

async function run() {
    const wasmUrl = chrome.runtime.getURL("pkg/EasyEncryptionService_bg.wasm");
    const bytes = await fetch(wasmUrl).then(r => r.arrayBuffer());
    await init({ module_or_path: bytes });

    async function loadContacts() {
        const { contacts = {} } = await chrome.storage.local.get("contacts");
        const select = document.getElementById("contactSelect");
        select.innerHTML = '<option value="">-- Select a contact --</option>';
        for (const name of Object.keys(contacts)) {
            const opt = document.createElement("option");
            opt.value = name;
            opt.textContent = name;
            select.appendChild(opt);
        }
    }

    document.getElementById("addContact").addEventListener("click", async () => {
        const name = document.getElementById("newContactName").value.trim();
        const key = document.getElementById("newContactKey").value.trim();
        const errorEl = document.getElementById("error");
        errorEl.textContent = "";

        if (!name || !key) {
            errorEl.textContent = "Enter both a name and a public key.";
            return;
        }

        const { contacts = {} } = await chrome.storage.local.get("contacts");
        contacts[name] = key;
        await chrome.storage.local.set({ contacts });

        document.getElementById("newContactName").value = "";
        document.getElementById("newContactKey").value = "";
        await loadContacts();
    });

    document.getElementById("deleteContact").addEventListener("click", async () => {
        const name = document.getElementById("contactSelect").value;
        if (!name) {
            document.getElementById("error").textContent = "Select a contact to delete first.";
            return;
        }
        const { contacts = {} } = await chrome.storage.local.get("contacts");
        delete contacts[name];
        await chrome.storage.local.set({ contacts });
        await loadContacts();
    });

    await loadContacts();

    const { pendingText } = await chrome.storage.local.get("pendingText");
    if (pendingText) {
        document.getElementById("input").value = pendingText;
        chrome.storage.local.remove("pendingText"); // consume it so it doesn't linger for next open
    }

    document.getElementById("encrypt").addEventListener("click", async () => {
        const text = document.getElementById("input").value;
        const name = document.getElementById("contactSelect").value;
        const errorEl = document.getElementById("error");
        errorEl.textContent = "";

        if (!name) {
            errorEl.textContent = "Select a recipient first.";
            return;
        }

        const { contacts = {} } = await chrome.storage.local.get("contacts");
        const key = contacts[name];
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