
// 1. PSEUDO-FALSE POSITIVES (Should be 100% IGNORED)
var unusedSecret = "donotreportme";
var obj = { key: "someProperty" };
var config = { secret: "123" };

// 2. TAINTED HARDCODED KEY (Chain)
var rawKey = "static-key-12345";
var intermediateKey = rawKey;
var finalKey = intermediateKey;

window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(12) },
    finalKey, // Traced back to rawKey
    new Uint8Array(10)
);

// 3. STATIC IV IN OBJECT
var staticIV = "fixed-iv-value";
var algoGCM = {
    name: "AES-GCM",
    iv: staticIV // Traced back to staticIV
};

crypto.subtle.encrypt(algoGCM, someKey, someData);

// 4. WEAK MODE (ECB)
var weakAlgo = { name: "AES-CBC", mode: "ECB" }; // Some libraries use this style
CryptoJS.AES.encrypt("msg", "pass", { mode: CryptoJS.mode.ECB });

// 5. DYNAMIC (Safe)
function safeEncrypt(dynamicKey) {
    window.crypto.subtle.encrypt({ name: "AES-GCM", iv: crypto.getRandomValues(new Uint8Array(12)) }, dynamicKey, data);
}

