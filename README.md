# **File Sharing Backend System*

## **Overview**

This project implements a file-sharing backend system using Go, AWS S3, PostgreSQL, Redis, JWT-based authentication, and WebSockets for real-time notifications. The system allows users to upload, retrieve, share, search, and delete files securely. It also includes periodic file expiration and deletion functionality.

---

## **Features**

1. **User Authentication:**
   - Register new users.
   - Login users with email and password.
   - JWT token-based authentication for secure access to file operations.

2. **File Operations:**
   - **Upload Files:** Files are encrypted using AES-256 and stored on AWS S3.
   - **Retrieve Files:** Users can view a list of uploaded files, cached using Redis for performance.
   - **Search Files:** Search files by name, upload date, or file type.
   - **Share Files:** Generate pre-signed URLs for sharing files.
   - **Delete Files:** Delete files from S3 and remove metadata from the database.
   - **Periodic Expired File Deletion:** A background worker that deletes expired files.

3. **WebSockets:**
   - Notify users in real-time when a file is successfully uploaded.

---

## **Technologies Used**

- **Go**: Main programming language.
- **PostgreSQL**: Database for storing user credentials and file metadata.
- **Redis**: Caching mechanism for file metadata.
- **AWS S3**: Cloud storage for file uploads.
- **JWT**: Token-based authentication.
- **WebSockets**: Real-time notifications for file uploads.

---

## **Requirements**

1. **Go** (1.18+)
2. **PostgreSQL** (14+)
3. **Redis** (v6+)
4. **AWS S3 Bucket**
5. **Gorilla Mux** (Routing)
6. **AWS SDK for Go**
7. **Bcrypt** (Password hashing)
8. **JWT** (For authentication)
9. **WebSockets** (For real-time notifications)

---

## **Installation**

### **Step 1: Clone the Repository**

```bash
git clone https://github.com/your-repo/filesharingbackend.git
cd filesharingbackend
```

### **Step 2: Install Dependencies**

```bash
go mod tidy
```

### **Step 3: Set Up PostgreSQL**

Create a new PostgreSQL database and user.

```sql
CREATE DATABASE trademarkia;
CREATE USER nishant WITH PASSWORD 'nishant';
GRANT ALL PRIVILEGES ON DATABASE trademarkia TO nishant;
```

Create necessary tables:

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    file_name TEXT NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    size BIGINT NOT NULL,
    email VARCHAR(255) REFERENCES users(email),
    expiration_date TIMESTAMP
);
```

### **Step 4: Set Up Redis**

Install and run Redis:

```bash
sudo apt-get install redis
redis-server
```

### **Step 5: Set Up AWS S3**

1. Create an S3 bucket on AWS.
2. Configure the correct AWS credentials in `~/.aws/credentials`:
   ```
   [default]
   aws_access_key_id = YOUR_ACCESS_KEY
   aws_secret_access_key = YOUR_SECRET_KEY
   ```
3. Replace the `awsS3BucketName` in the code with your actual S3 bucket name.

### **Step 6: Environment Variables**

Create an `.env` file to store sensitive data such as the JWT secret and AES encryption key:

```bash
JWT_SECRET="your_jwt_secret_key"
ENCRYPTION_KEY="a very secret and long key 1234!"
AWS_S3_BUCKET="your_bucket_name"
```

### **Step 7: Run the Application**

```bash
go run main.go
```

The server will start at `http://localhost:8080`.

---

## **API Endpoints**

### **1. User Registration**
**Endpoint:** `/register`  
**Method:** `POST`  
**Request Body:**

```json
{
    "email": "user@example.com",
    "password": "password"
}
```

**Response:** `201 Created`
```text
User registered successfully!
```

### **2. User Login**
**Endpoint:** `/login`  
**Method:** `POST`  
**Request Body:**

```json
{
    "email": "user@example.com",
    "password": "password"
}
```

**Response:** `200 OK`
```json
{
    "token": "your_jwt_token"
}
```

### **3. Upload File**
**Endpoint:** `/upload`  
**Method:** `POST`  
**Headers:**
```text
Authorization: Bearer <JWT Token>
```
**Form Data:**
```bash
file: <your_file>
```

**Response:** `200 OK`
```text
File uploaded successfully: filename.txt
```

### **4. Retrieve Files**
**Endpoint:** `/files`  
**Method:** `GET`  
**Headers:**
```text
Authorization: Bearer <JWT Token>
```

**Response:** `200 OK`
```json
[
    {
        "id": 1,
        "file_name": "example.txt",
        "upload_date": "2024-09-15T12:00:00Z",
        "size": 1024
    }
]
```

### **5. Search Files**
**Endpoint:** `/search?q=<query>&upload_date=<date>&file_type=<type>`  
**Method:** `GET`  
**Headers:**
```text
Authorization: Bearer <JWT Token>
```

**Response:** `200 OK`
```json
[
    {
        "id": 1,
        "file_name": "example.txt",
        "upload_date": "2024-09-15T12:00:00Z",
        "size": 1024
    }
]
```

### **6. Share File (Generate Pre-signed URL)**
**Endpoint:** `/share/{file_id}`  
**Method:** `GET`  
**Headers:**
```text
Authorization: Bearer <JWT Token>
```

**Response:** `200 OK`
```text
https://your-bucket-name.s3.amazonaws.com/your-file?AWSAccessKeyId=...
```

### **7. Delete File**
**Endpoint:** `/delete/{file_id}`  
**Method:** `DELETE`  
**Headers:**
```text
Authorization: Bearer <JWT Token>
```

**Response:** `200 OK`
```text
File deleted successfully: filename.txt
```

---

## **WebSocket Notifications**

**Endpoint:** `/ws`

The WebSocket connection provides real-time notifications for file uploads.

---

## **Background Task: Delete Expired Files**

A background worker runs every 24 hours to check and delete expired files from S3 and the database.

---

## **Testing**

To run tests for the project:

```bash
go test -v
```

---

## **Known Issues**

- **Database Connection:** Ensure the PostgreSQL database is running, and the correct credentials are provided.
- **AWS S3 Permissions:** Ensure that the AWS S3 bucket has the correct permissions for file uploads, downloads, and deletion.
  
---
