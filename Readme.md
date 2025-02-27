

# 🏡 **Blockchain-Based Land Registry and Marketplace**

A decentralized platform built on the Ethereum blockchain to register, buy, sell, and manage land parcels securely and transparently.

---

## 📌 **Table of Contents**
1. [Overview](#overview)
2. [Features](#features)
3. [Tech Stack](#tech-stack)
4. [Setup Instructions](#setup-instructions)
   - [Prerequisites](#prerequisites)
   - [Frontend Setup](#frontend-setup)
   - [Backend Setup](#backend-setup)
   - [Smart Contract Deployment](#smart-contract-deployment)
5. [Usage](#usage)
6. [Project Structure](#project-structure)
7. [Team Members](#team-members)
8. [Contributing](#contributing)
9. [License](#license)

---

## 🌟 **Overview**
This project is a blockchain-based solution for managing land ownership and facilitating secure property transactions. It combines the immutability of blockchain with user-friendly interfaces to create a seamless experience for registering, listing, and purchasing land parcels. The platform supports OAuth login for user authentication and MetaMask integration for blockchain interactions.

---

## ✨ **Features**
- **Land Registration**: Register new land parcels with details like address, area, and cost.
- **Marketplace**: List lands for sale and purchase available properties.
- **Decentralized Ownership**: Immutable land records stored on the blockchain.
- **OAuth Login**: User-friendly login via Google or other OAuth providers.
- **MetaMask Integration**: Connect your wallet to interact with the blockchain.
- **Event Syncing**: Backend listens to blockchain events and syncs data to a database for efficient querying.
- **Chatbot**: A simple chatbot to assist users with common queries.

---

## 💻 **Tech Stack**
- **Frontend**: React.js (Vite), Ethers.js, Web3Modal
- **Backend**: Node.js, Express.js, Ethers.js
- **Smart Contract**: Solidity, Hardhat
- **Blockchain**: Ethereum (Sepolia Testnet)
- **Storage**: MongoDB
- **Tools**: Infura/Alchemy (Ethereum node provider), Etherscan (contract verification)

---

## 🛠 **Setup Instructions**

### **Prerequisites**
1. Install **Node.js** and **npm**: [Download Node.js](https://nodejs.org/)
2. Install **MetaMask**: [Install MetaMask](https://metamask.io/)
3. Get **Sepolia ETH**: Use faucets like [Infura Faucet](https://www.infura.io/faucet/sepolia) or [Alchemy Faucet](https://sepoliafaucet.com/).
4. Create an account on [Infura](https://infura.io/) or [Alchemy](https://www.alchemy.com/) for Ethereum node access.
5. Sign up for an API key on [Etherscan](https://etherscan.io/) for contract verification.

---

### **Frontend Setup**
1. Navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file in the `frontend` folder:
   ```plaintext
   VITE_INFURA_URL=https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID
   VITE_CONTRACT_ADDRESS=0xYourDeployedContractAddressOnSepolia
   ```
4. Start the development server:
   ```bash
   npm run dev
   ```

---

### **Backend Setup**
1. Navigate to the `backend` directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file in the `backend` folder:
   ```plaintext
   DB_USER=your_db_user
   DB_HOST=localhost
   DB_NAME=land_registry
   DB_PASSWORD=your_db_password
   INFURA_URL=https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID
   CONTRACT_ADDRESS=0xYourDeployedContractAddressOnSepolia
   ```
4. Start the server:
   ```bash
   npm start
   ```

---

### **Smart Contract Deployment**
1. Navigate to the `smart-contract` directory:
   ```bash
   cd smart-contract
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Compile the contract:
   ```bash
   npx hardhat compile
   ```
4. Deploy the contract to Sepolia:
   ```bash
   npx hardhat run scripts/deploy.js --network sepolia
   ```
5. Verify the contract on Etherscan:
   ```bash
   npx hardhat verify --network sepolia 0xYourDeployedContractAddressOnSepolia
   ```

---

## 🚀 **Usage**
1. **Login**: Use OAuth (e.g., Google) to log in to the platform.
2. **Dashboard**:
   - Register new land parcels.
   - View registered lands.
   - List lands for sale.
3. **Marketplace**:
   - Browse available lands.
   - Purchase lands using MetaMask.
4. **Chatbot**: Ask questions about the platform or get assistance.

---

## 📂 **Project Structure**
```
hack-jmi/
├── frontend/
│   ├── public/
│   │   ├── vite.svg
│   ├── src/
│   │   ├── components/
│   │   │   ├── Auth.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Home.jsx
│   │   │   ├── Marketplace.jsx
│   │   │   └── Navbar.jsx
│   │   ├── App.jsx
│   │   ├── main.jsx
│   ├── package.json
├── backend/
│   ├── Controllers/
│   │   ├── AuthControllers.js
│   │   ├── UserControllers.js
│   ├── Models/
│   │   ├── propertyModel.js
│   │   ├── userModel.js
│   ├── Routers/
│   │   ├── AuthRoute.js
│   ├── app.js
│   ├── package.json
├── smart-contract/
│   ├── contracts/
│   │   └── LandRegistration.sol
│   ├── scripts/
│   │   └── deploy.js
│   ├── test/
│   │   └── LandRegistration.test.js
│   ├── hardhat.config.js
│   └── package.json
```

---

## 👥 **Team Members**
Here’s a list of our awesome team members and their roles:

| **Name**           | **Role**                     | **Responsibilities**                                                                 |
|---------------------|------------------------------|-------------------------------------------------------------------------------------|
| **Sambhav Mani Tripathi**     | Fullstack Developer                 | Building both frontend and backend, building chatbot, and ensuring smooth functionality across the stack.          |
| **Ayan Mani Tripathi**  | Frontend Developer           | Building the user interface, integrating MetaMask, and handling user interactions.  |
| **Manik Prakash**   | Backend Developer            | Setting up APIs, syncing blockchain events to the database, and managing user data. |
| **Arpit Mishra**| Web3/Blockchain Developer    | Writing, testing, and deploying smart contracts; integrating Ethers.js.     |



---

## 🤝 **Contributing**
We welcome contributions! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeatureName`).
3. Commit your changes (`git commit -m "Add YourFeatureName"`).
4. Push to the branch (`git push origin feature/YourFeatureName`).
5. Open a pull request.

---

## 📜 **License**
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**
- [Hardhat](https://hardhat.org/) for smart contract development and deployment.
- [Ethers.js](https://docs.ethers.org/) for interacting with the Ethereum blockchain.
- [Infura](https://infura.io/) and [Alchemy](https://www.alchemy.com/) for Ethereum node access.
- [Etherscan](https://etherscan.io/) for contract verification.

---
