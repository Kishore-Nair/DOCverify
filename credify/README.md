# 🛡️ Credify — Blockchain Document Authentication

**Credify** is a full-stack, blockchain-powered document authentication and fraud detection platform. It is designed to bridge the physical and digital verification worlds, allowing institutions to cryptographically anchor documents (such as university degrees, identity cards, and employment contracts) to the blockchain. Third parties can instantly verify a document's authenticity by scanning a generated QR code.

---

## ✨ Key Features

*   **⛓️ Blockchain Anchoring:** Documents are hashed via SHA-256 and securely logged on an EVM-compatible blockchain (Polygon/Hardhat) to guarantee immutability.
*   **🌐 Decentralized Storage (IPFS):** Documents are uploaded to IPFS. The system features a robust fallback mechanism that seamlessly stores files locally while preserving identical CID routing if the main IPFS network is unreachable.
*   **🤖 AI Fraud Detection:** Every uploaded document passes through a rigorous security heuristic pipeline:
    *   **Metadata & Font Consistency Checks:** Flags suspicious editing signatures (e.g., Photoshop, PDF Editors) and unusual font discrepancies.
    *   **AI-Generated Image Detection:** Deep-scans PNG/JPEG EXIF and chunk metadata to instantly reject synthetically generated images (Midjourney, DALL-E, Stable Diffusion, etc.).
    *   **Image Noise Analysis (ELA):** Detects localized digital tampering and splicing.
*   **📱 QR Code Verification:** Generates scannable QR codes for every verified document, allowing employers or border agents to verify physical copies instantly with their smartphone.
*   **🔐 Advanced Security:** 
    *   Role-Based Access Control (RBAC): Distinct dashboards and permissions for `citizens`, `verifiers`, and `admins`.
    *   Mandatory Email Verification (OTP).
    *   Time-based One-Time Passwords (TOTP) / 2FA.
    *   Comprehensive Administrative KYC Review Portal with structured rejection reasons.

---

## 🏗️ Architecture Stack

*   **Backend:** Python 3.12, Flask, Flask-SQLAlchemy, Flask-Login, Flask-JWT-Extended
*   **Database:** SQLite (Development) / PostgreSQL (Production ready via SQLAlchemy)
*   **Blockchain Engine:** Solidity, Hardhat, Web3.py
*   **Frontend:** HTML5, Vanilla CSS3 (Custom Design System), Jinja2 Templating, Inline SVG Heroicons
*   **AI/Forensics:** PyPDF, Pillow (Image Processing)

---

## 🚀 Getting Started

### 1. Prerequisites
*   Python 3.10+
*   Node.js & npm (for Hardhat)
*   IPFS Desktop or CLI (Optional, system falls back to local storage automatically)

### 2. Installation

Clone the repository and set up your Python virtual environment:
```bash
git clone https://github.com/Kishore-Nair/DOCverify.git
cd credify

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Blockchain Setup (Hardhat)

Navigate to the blockchain directory, install dependencies, and spin up a local RPC node:
```bash
cd blockchain
npm install
npx hardhat node
```
*Leave this terminal window open to keep the local blockchain running.*

In a new terminal window, deploy the smart contract to your local network:
```bash
cd blockchain
npx hardhat run scripts/deploy.js --network localhost
```

### 4. Environment Configuration

Create a `.env` file in the root of the project and populate it with your specific credentials:
```env
# Flask Settings
SECRET_KEY=super-secret-development-key
DATABASE_URL=sqlite:///credify.db

# Blockchain
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
PRIVATE_KEY=<your_hardhat_wallet_private_key>
CONTRACT_ADDRESS=<deployed_contract_address_from_step_3>

# IPFS
IPFS_API_URL=http://127.0.0.1:5001/api/v0
```

### 5. Running the Application

Ensure your virtual environment is active, then initialize the database and run the server:
```bash
# Initialize the database
python scripts/init_db.py

# Start the Flask development server
python run.py
```
The application will now be running at `http://127.0.0.1:5000` (or your local IP address).

---

## 📱 How to Demo the QR Verification

To demonstrate real-time mobile verification:
1. Ensure the Flask server is running and bound to `0.0.0.0` (which is the default in `run.py`).
2. Find your machine's local network IP address (e.g., `192.168.x.x` or `10.x.x.x`).
3. On your Mac browser, go to `http://<YOUR_LOCAL_IP>:5000` and log in.
4. Upload a document to generate a Verification Report and its associated QR code.
5. Open your smartphone's camera (make sure your phone is connected to the same Wi-Fi network) and scan the QR code displayed on your screen.
6. Your phone will seamlessly open the portal and cryptographically verify the document!

---

## 👨‍💻 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. Ensure all tests and heuristic checks pass before submitting.

## 📝 License
This project is licensed under the MIT License.
