chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "encrypt-selection",
        title: "Encrypt with EES",
        contexts: ["selection"]
    });
    chrome.contextMenus.create({
        id: "decrypt-selection",
        title: "Decrypt with EES",
        contexts: ["selection"]
    });
});

function openPopupWindow() {
    chrome.windows.create({
        url: chrome.runtime.getURL("popup.html"),
        type: "popup",
        width: 360,
        height: 480
    });
}

chrome.action.onClicked.addListener(() => {
    openPopupWindow();
});

chrome.contextMenus.onClicked.addListener(async (info) => {
    if (info.menuItemId === "encrypt-selection" && info.selectionText) {
        await chrome.storage.local.set({ pendingText: info.selectionText});
        openPopupWindow();
    } else if (info.menuItemId === "decrypt-selection" && info.selectionText) {
        await chrome.storage.local.set({ pendingText: info.selectionText});
        openPopupWindow();
    }
});