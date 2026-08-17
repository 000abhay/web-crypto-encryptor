# Password Encryptor

A small, static browser application for encrypting and decrypting text with a secret key you choose. It is ready to host on GitHub Pages: no build step, server, database, analytics, or network API is used.

## How it works

1. Enter text and a secret key, then select **Encrypt**.
2. Copy the encrypted result somewhere safe.
3. To recover it later, paste that encrypted result into the input, enter the exact same secret key, and select **Decrypt**.

Encryption happens locally in the browser. The secret key is entered only at runtime, is not hardcoded, is never saved to localStorage or sessionStorage, is never included in the encrypted output, and is never sent to a server. If you forget it, it cannot be recovered.

## Cryptography

- A unique 16-byte cryptographic salt and 12-byte IV are generated for every encryption with `crypto.getRandomValues()`.
- The secret key is converted into a non-extractable AES-256 key with PBKDF2-HMAC-SHA-256 and 600,000 iterations.
- Text is authenticated and encrypted with AES-GCM through the browser Web Crypto API.
- The output format is `pwe1:` followed by a Base64URL-encoded, versioned payload containing the salt, IV, and ciphertext. Base64URL makes binary data portable as text; it is not encryption.

The salt and IV may be public. The secret key is the only information required to decrypt and is intentionally not part of the output.

## Run and deploy

Open `index.html` in a current browser, or deploy the repository root with **GitHub Pages**:

1. Push these files to GitHub.
2. In the repository, open **Settings → Pages**.
3. Choose **Deploy from a branch**, then select `main` and `/ (root)`.
4. Save.

GitHub Pages serves the application over HTTPS, which supports the Clipboard and Web Crypto APIs.

## Security note

This application is intended as a client-side encryption utility and educational project. Never use an untested encryption implementation for highly sensitive information without understanding and independently reviewing its security properties.

Keep backup copies of both the encrypted text and the secret key in appropriate secure locations. A lost secret key cannot be recovered.
