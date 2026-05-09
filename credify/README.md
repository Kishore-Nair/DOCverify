# Credify

A blockchain-based document authentication and fraud detection system.

## Architecture

The project is structured as a monorepo with the following components:

- **frontend**: A React 18 application built with Vite, TypeScript, Tailwind CSS, and shadcn/ui. Handles the user interface, wallet connection (ethers.js v6), state management (Zustand), and routing (React Router v6).
- **backend**: The main API built with FastAPI (Python 3.11). Manages user accounts, authentication (JWT), relational data (PostgreSQL/SQLAlchemy), and orchestrates interactions with the blockchain and AI services.
- **ai-service**: A microservice built with FastAPI (Python 3.11) dedicated to machine learning and forensic analysis of documents using OpenCV, PyMuPDF, Transformers, and scikit-learn.
- **blockchain**: Smart contracts and deployment scripts using Hardhat and Solidity, targeting the Polygon Mumbai testnet.
- **Storage**: MinIO is used as an S3-compatible off-chain object storage for documents. PostgreSQL is used for relational database needs.

## Getting Started

1. Copy `.env.example` to `.env` and fill in the required values.
2. Run the application suite using Docker Compose:

```bash
docker-compose up --build
```
