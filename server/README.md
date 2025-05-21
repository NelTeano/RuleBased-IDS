## Signature-Based IDS Server Setup Guide

This guide will help you set up and run the Flask-based server for your Signature-Based Intrusion Detection System (IDS).

### Setup ENV Variables

- `
    SERVER_PORT=5000
    IDS_PORT= 3000
`

### Prerequisites

- Python 3.8 or higher
- [pip](https://pip.pypa.io/en/stable/installation/)
- (Optional, for rate limiting) [Redis](https://redis.io/) server running locally or remotely

### 1. Clone or Download the Project

Download or clone the repository to your local machine.

### 2. Create and Activate a Virtual Environment (Recommended)

Open a terminal in the `server` directory and run:

```
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Python Dependencies

Install all required packages using pip:

```
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the `server` directory with the following content (edit ports as needed):

```
SERVER_PORT=5000
IDS_PORT=5114
```

### 5. (Optional) Set Up Redis for Rate Limiting

If you want to use Redis for Flask-Limiter (recommended for production):
- Install Redis and start the server (see [Redis Quick Start](https://redis.io/docs/getting-started/)).
- The default config in `app.py` uses `redis://localhost:6379`.

### 6. Run the Flask Server

In the `server` directory, start the app:

```
python app.py
```

You should see output indicating the server and IDS ports.

### 7. API Usage

- The main API routes are registered under `/api/ids` (see `routes/IDSRoutes.py`).
- Example: `POST http://localhost:5000/api/ids/trigger-intrusion`

---

**Troubleshooting:**
- Ensure your `.env` file is present and correct.
- If you see a warning about Flask-Limiter storage, make sure Redis is running or remove the `storage_uri` for development.
- For Windows, always activate your virtual environment before running the app.

---


## Test Routes 

**Trigger Intrusion Route**

- `http://127.0.0.1:<SERVER-PORT>/api/ids/trigger-intrusion`

```shell
{
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "intrusion_type": "Syn Scan",
  "timestamp": "2025-05-21T10:32:00Z"
}
```



**For more details, see the main project README in the parent directory.**
