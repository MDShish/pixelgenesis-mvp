# pixelgenesis-mvp

---

# 🌐 PixelGenesis — Decentralized Identity MVP

A lightweight, fully local, privacy-first decentralized identity (DID) platform built with **Flask**, featuring **Ed25519 DIDs**, **Selective Disclosure**, **Predicate Proofs**, **AES-256 Encrypted File Sharing**, **Shamir Secret Recovery**, and **IPFS-style storage simulation** — all without paid APIs.

---

## 🚀 Features

### ✅ 1. **Decentralized Identity (DID) Generation**

* One-click Ed25519 keypair generation
* Creates local DID Document
* Private keys stored securely on the user side

---

### 🔐 2. **User Authentication**

* Login using private key
* Fully decentralized — no passwords
* Keys never leave the device

---

### 🧍‍♂️ 3. **User Profile Creation**

Store user identity attributes:

* Name
* DOB
* Gender
* Aadhaar Hash
  All data is stored locally and never shared without consent.

---

### 🎫 4. **Token Generation (Selective Disclosure)**

Three modes:

#### **🔵 Mode A — Value Disclosure**

Share a specific attribute:
`name`, `dob`, `gender`, `aadhaar_hash`

#### **🟣 Mode B — Predicate Token**

Verify conditions without revealing actual data:
Examples:

* `age > 18`
* `gender == male`
* `city in [“blr”, “hyd”]`

Zero-knowledge style verification (logic only).

#### **🟡 Mode C — File Upload + AES Encryption**

* Upload any file
* AES-256 encrypt
* Split AES key using **Shamir’s Secret Sharing (2-of-3)**
* Upload encrypted file
* Store IPFS-style local CID

---

### 🔑 5. **Shamir Secret Recovery**

* Recover AES key using any **2 out of 3 shares**
* Decrypt uploaded file securely

---

### 📨 6. **Token Verification**

* Validates signature
* Checks expiry (TTL)
* Checks revoked or not
* Verifies predicates or shared values

---

### 📜 7. **VC Signing (Verifiable Credential)**

Sign a JSON credential using DID private key:

Example:

```json
{
  "name": "John Doe",
  "verified": true,
  "issuer": "did:pg:xyz123"
}
```

---

### 🗂️ 8. **Tokens List / Audit Log**

View all active tokens:

* Time
* Mode
* Status
* Expiry
* File CIDs

---

### 🌑 Beautiful UI

* Fully mobile-responsive
* Dark + light mode friendly colors
* Clean container & components

---

## 🏗️ Project Structure

```
pixelgenesis_mvp/
│── app.py
│── requirements.txt
│── README.md
│── user_db.json
│── static/
│   └── style.css
│── templates/
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── userdata.html
│   ├── userdata_success.html
│   ├── tokens.html
│   ├── access_request.html
│   ├── access_success.html
│   ├── verify_access.html
│   └── shamir_recover.html
└── uploads/    (ignored in .gitignore)
```

---

## ⚙️ Tech Stack

### **Backend**

* Python
* Flask
* Ed25519 (cryptography)
* AES-256 encryption
* Shamir Secret Sharing
* UUID token infra

### **Frontend**

* HTML + CSS
* Dark-theme UI
* Clean components

---

## 🧪 How It Works (Flow)

### 1️⃣ Create DID → generates keys

### 2️⃣ Login using private key

### 3️⃣ Add identity data

### 4️⃣ Generate token

* Choose Mode A / B / C
* TTL
* Create signed access token

### 5️⃣ Share token

### 6️⃣ Receiver verifies token

---

## 🚀 Deploy on Render

### Build command:

```
pip install -r requirements.txt
```

### Start command:

```
gunicorn app:app
```

---

## 📌 Requirements File (Add this as requirements.txt)

```
flask
cryptography
pycryptodome
secretsharing
gunicorn
```

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

## 👨‍💻 Author

**MD Shish**
GitHub: [https://github.com/MDShish](https://github.com/MDShish)


