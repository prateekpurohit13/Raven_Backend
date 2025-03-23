# RAVEN Backend

## 📌 Overview
RAVEN is an open-source API security tool that focuses on **API visibility** before implementing scanning features. The backend is built using **Golang**, **Kafka**, **MongoDB**, and **Redis**, with the initial feature focusing on extracting API inventory data from `.har` files.

## ⚙️ Tech Stack
- **Backend:** Golang (Gin framework)
- **Message Queue:** Kafka
- **Database:** MongoDB, Redis
- **Frontend:** Next.js (Planned for future development)

## 🚀 Features (MVP)
- Upload `.har` files and extract API inventory data.
- Store API metadata in MongoDB.
- Provide a dashboard for API visibility.
- Future: eBPF-based real-time API discovery.

## 🛠 Installation & Setup

### 1️⃣ Clone the Repository
```sh
git clone https://github.com/RavenSec10/Raven_Backend.git
cd Raven_Backend
```

### 2️⃣ Install Dependencies
Make sure you have **Go 1.20+** installed. Then, run:
```sh
go mod tidy
```

### 3️⃣ Run the Backend Server
```sh
go run main.go
```
The backend should now be running on **http://localhost:8080**.

## 📂 Project Structure
```plaintext
Raven_Backend/
│── cmd/               # Entry points for the application
│── internal/          # Internal packages (routes, services, handlers)
│── pkg/              # Shared utilities
│── har_parser/       # Logic to process .har files
│── db/               # Database connection setup
│── configs/          # Configuration files
│── main.go           # Main entry point
│── Dockerfile        # Containerization setup
│── README.md         # Project documentation
```

## 📡 API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Health check |
| `POST` | `/upload-har` | Upload `.har` file and extract API data |

## 🔜 Roadmap
- [ ] **Improve API Inventory extraction**
- [ ] **Add MongoDB and Redis integration**
- [ ] **Implement eBPF-based API discovery**
- [ ] **Build API security testing features**
- [ ] **Develop frontend dashboard using Next.js**

## 🤝 Contributing
Contributions are welcome! Feel free to fork the repo, create a new branch, and submit a PR.

## 📜 License
This project is open-source and available under the **MIT License**.

---
🚀 **Built with ❤️ by the RavenSec Team**

