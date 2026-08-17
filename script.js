"use strict";

// Versioned, portable format: pwe1:<base64url(version | salt | iv | ciphertext)>
// PBKDF2-HMAC-SHA-256 at 600,000 iterations follows current OWASP guidance for
// password storage and keeps the derivation cost meaningful in modern browsers.
const FORMAT_PREFIX = "pwe1:";
const FORMAT_VERSION = 1;
const PBKDF2_ITERATIONS = 600000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const elements = {
  form: document.querySelector("#crypto-form"),
  sourceText: document.querySelector("#source-text"),
  secretKey: document.querySelector("#secret-key"),
  toggleKey: document.querySelector("#toggle-key"),
  encryptButton: document.querySelector("#encrypt-button"),
  decryptButton: document.querySelector("#decrypt-button"),
  resultWrapper: document.querySelector("#result-wrapper"),
  resultText: document.querySelector("#result-text"),
  resultMask: document.querySelector("#result-mask"),
  toggleResult: document.querySelector("#toggle-result"),
  resultType: document.querySelector("#result-type"),
  copyButton: document.querySelector("#copy-button"),
  clearButton: document.querySelector("#clear-button"),
  statusMessage: document.querySelector("#status-message"),
  inputCount: document.querySelector("#input-count"),
};

function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

function generateIV() {
  return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
}

async function deriveKey(password, salt) {
  const passwordMaterial = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    passwordMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = "";

  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function base64ToArrayBuffer(base64) {
  const standardBase64 = base64.replaceAll("-", "+").replaceAll("_", "/");
  const paddedBase64 = standardBase64.padEnd(Math.ceil(standardBase64.length / 4) * 4, "=");
  const binary = atob(paddedBase64);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes.buffer;
}

function encodeEncryptedPayload(salt, iv, ciphertext) {
  const payload = new Uint8Array(1 + salt.length + iv.length + ciphertext.byteLength);
  payload[0] = FORMAT_VERSION;
  payload.set(salt, 1);
  payload.set(iv, 1 + salt.length);
  payload.set(new Uint8Array(ciphertext), 1 + salt.length + iv.length);
  return `${FORMAT_PREFIX}${arrayBufferToBase64(payload)}`;
}

function decodeEncryptedPayload(value) {
  const normalizedValue = value.trim();

  if (!normalizedValue.startsWith(FORMAT_PREFIX)) {
    throw new Error("Unsupported encrypted text format.");
  }

  const payload = new Uint8Array(base64ToArrayBuffer(normalizedValue.slice(FORMAT_PREFIX.length)));
  const minimumLength = 1 + SALT_LENGTH + IV_LENGTH + 16;

  if (payload.length < minimumLength || payload[0] !== FORMAT_VERSION) {
    throw new Error("Invalid encrypted text.");
  }

  return {
    salt: payload.slice(1, 1 + SALT_LENGTH),
    iv: payload.slice(1 + SALT_LENGTH, 1 + SALT_LENGTH + IV_LENGTH),
    ciphertext: payload.slice(1 + SALT_LENGTH + IV_LENGTH),
  };
}

async function encryptText(plaintext, password) {
  const salt = generateSalt();
  const iv = generateIV();
  const key = await deriveKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEncoder.encode(plaintext));
  return encodeEncryptedPayload(salt, iv, ciphertext);
}

async function decryptText(encryptedText, password) {
  const { salt, iv, ciphertext } = decodeEncryptedPayload(encryptedText);
  const key = await deriveKey(password, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return textDecoder.decode(plaintext);
}

function setStatus(message = "", state = "") {
  elements.statusMessage.textContent = message;
  elements.statusMessage.className = `status-message${state ? ` is-${state}` : ""}`;
}

function setResult(value, type) {
  elements.resultText.value = value;
  elements.copyButton.disabled = !value;
  elements.toggleResult.disabled = !value;
  elements.resultType.textContent = type;
  elements.resultType.hidden = !type;
  updateResultMask(value);
  setResultVisibility(false);
}

function updateResultMask(value) {
  const visibleDots = Math.max(8, Math.min(Array.from(value).length, 72));
  elements.resultMask.textContent = value ? "•".repeat(visibleDots) : "";
}

function setResultVisibility(isVisible) {
  const hasResult = Boolean(elements.resultText.value);
  const shouldShowMask = hasResult && !isVisible;
  elements.resultWrapper.classList.toggle("is-masked", shouldShowMask);
  elements.resultMask.hidden = !shouldShowMask;
  elements.toggleResult.classList.toggle("is-visible", isVisible && hasResult);
  elements.toggleResult.setAttribute("aria-label", isVisible ? "Hide result" : "Show result");
  elements.toggleResult.setAttribute("aria-pressed", String(isVisible && hasResult));
}

function setBusy(isBusy, operation = "") {
  elements.encryptButton.disabled = isBusy;
  elements.decryptButton.disabled = isBusy;
  elements.copyButton.disabled = isBusy || !elements.resultText.value;
  elements.clearButton.disabled = isBusy;
  elements.encryptButton.querySelector("span").textContent = isBusy && operation === "encrypt" ? "Encrypting…" : "Encrypt";
  elements.decryptButton.querySelector("span").textContent = isBusy && operation === "decrypt" ? "Decrypting…" : "Decrypt";
}

function validateInputs() {
  if (!window.crypto?.subtle) {
    setStatus("Web Crypto is unavailable. Open this page in a current browser over HTTPS.", "error");
    return false;
  }

  if (!elements.sourceText.value) {
    setStatus("Enter text to encrypt or encrypted text to decrypt.", "error");
    elements.sourceText.focus();
    return false;
  }

  if (!elements.secretKey.value) {
    setStatus("Enter a secret key to continue.", "error");
    elements.secretKey.focus();
    return false;
  }

  return true;
}

async function handleEncryption() {
  if (!validateInputs()) return;

  setBusy(true, "encrypt");
  setStatus("Encrypting locally…", "working");

  try {
    const encryptedText = await encryptText(elements.sourceText.value, elements.secretKey.value);
    setResult(encryptedText, "Encrypted text");
    setStatus("Encryption successful. Copy the result and keep your secret key safe.", "success");
  } catch {
    setStatus("Unable to encrypt this text. Please try again.", "error");
  } finally {
    setBusy(false);
  }
}

async function handleDecryption() {
  if (!validateInputs()) return;

  setBusy(true, "decrypt");
  setStatus("Decrypting locally…", "working");

  try {
    const plaintext = await decryptText(elements.sourceText.value, elements.secretKey.value);
    setResult(plaintext, "Decrypted text");
    setStatus("Decryption successful.", "success");
  } catch {
    setResult("", "");
    setStatus("Unable to decrypt. The secret key may be incorrect or the encrypted data may be corrupted.", "error");
  } finally {
    setBusy(false);
  }
}

async function copyResult() {
  const result = elements.resultText.value;
  if (!result) return;

  try {
    await navigator.clipboard.writeText(result);
  } catch {
    elements.resultText.select();
    const copied = document.execCommand("copy");
    window.getSelection()?.removeAllRanges();
    if (!copied) {
      setStatus("Could not copy automatically. Select the result and copy it manually.", "error");
      return;
    }
  }

  setStatus("Result copied to your clipboard.", "success");
}

function clearAll() {
  elements.form.reset();
  setResult("", "");
  setStatus("");
  updateCharacterCount();
  elements.sourceText.focus();
}

function updateCharacterCount() {
  const count = elements.sourceText.value.length;
  elements.inputCount.textContent = `${count.toLocaleString()} character${count === 1 ? "" : "s"}`;
}

elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  handleEncryption();
});

elements.decryptButton.addEventListener("click", handleDecryption);
elements.copyButton.addEventListener("click", copyResult);
elements.clearButton.addEventListener("click", clearAll);
elements.sourceText.addEventListener("input", updateCharacterCount);

elements.toggleResult.addEventListener("click", () => {
  const isHidden = elements.resultWrapper.classList.contains("is-masked");
  setResultVisibility(isHidden);
});

elements.toggleKey.addEventListener("click", () => {
  const isHidden = elements.secretKey.type === "password";
  elements.secretKey.type = isHidden ? "text" : "password";
  elements.toggleKey.classList.toggle("is-visible", isHidden);
  elements.toggleKey.setAttribute("aria-label", isHidden ? "Hide secret key" : "Show secret key");
  elements.toggleKey.setAttribute("aria-pressed", String(isHidden));
});

updateCharacterCount();
