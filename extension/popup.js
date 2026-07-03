import init, { encrypt_message, decrypt_message } from "./pkg/EasyEncryptionService.js";

// Helpers to persist file containing private key
function openHandleDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open("ees-handles", 1);
        req.onupgradeneeded = () => req.result.createObjectStore("handles");
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function saveHandle(handle) {
    const db = await openHandleDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction("handles", "readwrite");
        tx.objectStore("handles").put(handle, "privateKey");
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

async function loadHandle() {
    const db = await openHandleDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction("handles", "readonly");
        const req = tx.objectStore("handles").get("privateKey");
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
    });
}

let currentKeyHandle = null;

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

    document.getElementById("selectKey").addEventListener("click", async () => {
        try {
            const [handle] = await window.showOpenFilePicker({
                types: [{ description: "PKCS8 key", accept: { "application/octet-stream": [".pkcs8"] } }]
            });
            await saveHandle(handle);
            currentKeyHandle = handle;
            document.getElementById("keyFileName").textContent = handle.name;
        } catch (err) {
            if (err.name !== "AbortError") {
                document.getElementById("error").textContent = `Error: ${err.message}`;
            }
        }
    });

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

    const savedHandle = await loadHandle();
    if (savedHandle) {
        const perm = await savedHandle.queryPermission({ mode: "read" });
        currentKeyHandle = savedHandle;
        document.getElementById("keyFileName").textContent =
            perm === "granted" ? savedHandle.name : `${savedHandle.name} (click Select to re-confirm)`;
    }

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
        const errorEl = document.getElementById("error");
        errorEl.textContent = "";

        if (!currentKeyHandle) {
            errorEl.textContent = "Select your private key file first.";
            return;
        }

        try {
            const perm = await currentKeyHandle.queryPermission({ mode: "read" });
            if (perm !== "granted") {
                const req = await currentKeyHandle.requestPermission({ mode: "read" });
                if (req !== "granted") {
                    errorEl.textContent = "Permission to read the key file was denied.";
                    return;
                }
            }
            const file = await currentKeyHandle.getFile();
            const buffer = await file.arrayBuffer();
            const keyBytes = new Uint8Array(buffer);
            const decryptedText = decrypt_message(packed, keyBytes);
            keyBytes.fill(0);
            document.getElementById("decrypted").textContent = decryptedText;
            document.getElementById("decryptResults").style.display = "block";
        } catch (err) {
            errorEl.textContent = `Decrypt error: ${err.message || err}`;
        }
    });
}

run();