package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var clients = make(map[*websocket.Conn]bool) // Track active WebSocket clients
var broadcast = make(chan string)            // Channel for broadcasting messages

// Global variables for DB, Redis, and AWS S3
var (
	db              *sql.DB
	redisClient     *redis.Client
	jwtKey          = []byte("your_secret_key") // Secret key for JWT signing
	awsS3BucketName = "trademarkia-21bce2983"   // Update this to your actual bucket name
)
var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// User struct for login and registration
type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// JWT Claims structure
type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

// Initialize the database connection
func initDB() {
	connStr := "user=nishant password=nishant dbname=trademarkia sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping the database:", err)
	}

	fmt.Println("Connected to the database successfully!")
}

// Initialize Redis connection
func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	_, err := redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	fmt.Println("Connected to Redis successfully!")
}

// Initialize AWS session
func initAWSSession() *session.Session {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"), // Ensure the region is correct
	})
	if err != nil {
		log.Fatal("Failed to create AWS session:", err)
	}
	return sess
}

// Upload file to S3
func uploadToS3(sess *session.Session, fileName string, file io.ReadSeeker) error {
	s3Svc := s3.New(sess)

	result, err := s3Svc.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(awsS3BucketName),
		Key:    aws.String(fileName),
		Body:   file,
	})
	if err != nil {
		log.Printf("S3 Upload Error: %v", err)
		return err
	}

	log.Printf("Successfully uploaded %s to S3 with result: %v", fileName, result)
	return nil
}

// Generate Pre-signed URL for S3
func generatePresignedURL(sess *session.Session, fileName string) (string, error) {
	s3Svc := s3.New(sess)
	req, _ := s3Svc.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(awsS3BucketName),
		Key:    aws.String(fileName),
	})
	urlStr, err := req.Presign(24 * time.Hour) // Pre-signed URL valid for 24 hours
	if err != nil {
		log.Printf("Failed to generate pre-signed URL: %v", err)
		return "", err
	}
	return urlStr, nil
}

// Registration handler
// Registration handler
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Attempt to insert user into the database
	_, err = db.Exec("INSERT INTO users (email, password_hash, created_at) VALUES ($1, $2, $3)", user.Email, string(hashedPassword), time.Now())
	if err != nil {
		// Log the error for debugging
		log.Printf("Error inserting user: %v", err)
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "User registered successfully!")
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var hashedPassword string
	err = db.QueryRow("SELECT password_hash FROM users WHERE email = $1", user.Email).Scan(&hashedPassword)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(7 * 24 * time.Hour) // expire in 7 days
	claims := &Claims{
		Email: user.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// JWT Authentication middleware
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		} else {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// File upload handler with detailed error handling
// Upload File Handler with encryption
// Upload File Handler with encryption
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20) // 10MB max
	if err != nil {
		http.Error(w, "Error parsing form data: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the file content into memory
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Encrypt the file content with a valid 32-byte key for AES-256
	encryptionKey := []byte("a very secret and long key 1234!") // Now exactly 32 bytes
	encryptedContent, err := encryptFile(fileBytes, encryptionKey)
	if err != nil {
		http.Error(w, "Error encrypting file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a ReadSeeker for S3 upload
	encryptedReader := bytes.NewReader(encryptedContent)

	// Initialize AWS session
	sess := initAWSSession()
	if sess == nil {
		http.Error(w, "Failed to create AWS session", http.StatusInternalServerError)
		return
	}

	// Upload the encrypted file to S3
	err = uploadToS3(sess, handler.Filename, encryptedReader)
	if err != nil {
		http.Error(w, "Failed to upload to S3: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store file metadata in the database
	claims := r.Context().Value("claims").(*Claims)
	userEmail := claims.Email
	_, err = db.Exec("INSERT INTO files (file_name, upload_date, size, email) VALUES ($1, $2, $3, $4)",
		handler.Filename, time.Now(), handler.Size, userEmail)
	if err != nil {
		http.Error(w, "Error saving file metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Clear Redis cache for the user's files
	redisClient.Del(context.Background(), "files_"+userEmail)

	// Notify WebSocket clients that the upload is complete
	notifyFileUploadCompleted(handler.Filename)

	// Response to client
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File uploaded successfully: %s\n", handler.Filename)
}

// File retrieval handler with Redis caching
func getFilesHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userEmail := claims.Email
	ctx := context.Background()

	cachedData, err := redisClient.Get(ctx, "files_"+userEmail).Result()
	if err == redis.Nil {
		rows, err := db.Query("SELECT id, file_name, upload_date, size FROM files WHERE email = $1", userEmail)
		if err != nil {
			http.Error(w, "Error retrieving files", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var files []map[string]interface{}
		for rows.Next() {
			var id int
			var fileName string
			var uploadDate time.Time
			var size int64
			err := rows.Scan(&id, &fileName, &uploadDate, &size)
			if err != nil {
				http.Error(w, "Error scanning file metadata", http.StatusInternalServerError)
				return
			}
			files = append(files, map[string]interface{}{
				"id":          id,
				"file_name":   fileName,
				"upload_date": uploadDate,
				"size":        size,
			})
		}

		jsonData, _ := json.Marshal(files)
		redisClient.Set(ctx, "files_"+userEmail, jsonData, time.Minute*5)

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonData)
	} else if err != nil {
		http.Error(w, "Error retrieving cache", http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(cachedData))
	}
}

// File search handler
func searchFilesHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userEmail := claims.Email

	query := r.URL.Query().Get("q")
	dateQuery := r.URL.Query().Get("upload_date")
	fileTypeQuery := r.URL.Query().Get("file_type")

	var rows *sql.Rows
	var err error

	if query != "" {
		// Search by file name
		rows, err = db.Query("SELECT id, file_name, upload_date, size FROM files WHERE email = $1 AND file_name ILIKE '%' || $2 || '%'", userEmail, query)
	} else if dateQuery != "" {
		// Search by upload date
		rows, err = db.Query("SELECT id, file_name, upload_date, size FROM files WHERE email = $1 AND upload_date::text LIKE '%' || $2 || '%'", userEmail, dateQuery)
	} else if fileTypeQuery != "" {
		// Search by file type (based on file extension)
		rows, err = db.Query("SELECT id, file_name, upload_date, size FROM files WHERE email = $1 AND file_name ILIKE '%' || $2", userEmail, fileTypeQuery)
	} else {
		http.Error(w, "No search parameters provided", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Error searching for files", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var id int
		var fileName string
		var uploadDate time.Time
		var size int64
		err := rows.Scan(&id, &fileName, &uploadDate, &size)
		if err != nil {
			http.Error(w, "Error scanning file metadata", http.StatusInternalServerError)
			return
		}
		files = append(files, map[string]interface{}{
			"id":          id,
			"file_name":   fileName,
			"upload_date": uploadDate,
			"size":        size,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

// File sharing handler (Generate pre-signed URL)
func shareFileHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userEmail := claims.Email
	fileID := mux.Vars(r)["file_id"]

	// Retrieve file name from database based on file ID and user
	var fileName string
	err := db.QueryRow("SELECT file_name FROM files WHERE id = $1 AND email = $2", fileID, userEmail).Scan(&fileName)
	if err != nil {
		http.Error(w, "File not found or unauthorized access", http.StatusNotFound)
		return
	}

	// Generate pre-signed URL for the file
	sess := initAWSSession()
	url, err := generatePresignedURL(sess, fileName)
	if err != nil {
		http.Error(w, "Error generating URL", http.StatusInternalServerError)
		return
	}

	// Return the pre-signed URL
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, url) // Return the URL directly in plain text
}

// File delete handler (Delete from S3, DB, and Redis)
func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userEmail := claims.Email
	fileID := mux.Vars(r)["file_id"]

	// Retrieve file name from the database based on file ID and user
	var fileName string
	err := db.QueryRow("SELECT file_name FROM files WHERE id = $1 AND email = $2", fileID, userEmail).Scan(&fileName)
	if err != nil {
		http.Error(w, "File not found or unauthorized access", http.StatusNotFound)
		return
	}

	// Initialize AWS session
	sess := initAWSSession()
	s3Svc := s3.New(sess)

	// Delete file from S3
	_, err = s3Svc.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(awsS3BucketName),
		Key:    aws.String(fileName),
	})
	if err != nil {
		http.Error(w, "Error deleting file from S3", http.StatusInternalServerError)
		return
	}

	// Remove the file metadata from the database
	_, err = db.Exec("DELETE FROM files WHERE id = $1 AND email = $2", fileID, userEmail)
	if err != nil {
		http.Error(w, "Error deleting file metadata from database", http.StatusInternalServerError)
		return
	}

	// Clear the Redis cache for the user's files
	redisClient.Del(context.Background(), "files_"+userEmail)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File deleted successfully: %s\n", fileName)
}

// Function to periodically delete expired files
func deleteExpiredFiles() {
	ticker := time.NewTicker(24 * time.Hour) // Run the job every 24 hours
	defer ticker.Stop()

	for {
		<-ticker.C // Wait for the next tick

		// Find expired files
		rows, err := db.Query("SELECT id, file_name FROM files WHERE expiration_date <= NOW()")
		if err != nil {
			log.Printf("Error querying expired files: %v", err)
			continue
		}

		defer rows.Close()

		var fileID int
		var fileName string

		// Loop through each expired file
		for rows.Next() {
			if err := rows.Scan(&fileID, &fileName); err != nil {
				log.Printf("Error scanning file: %v", err)
				continue
			}

			// Delete from S3
			sess := initAWSSession()
			s3Svc := s3.New(sess)
			_, err := s3Svc.DeleteObject(&s3.DeleteObjectInput{
				Bucket: aws.String(awsS3BucketName),
				Key:    aws.String(fileName),
			})
			if err != nil {
				log.Printf("Error deleting file %s from S3: %v", fileName, err)
				continue
			}

			// Delete from the database
			_, err = db.Exec("DELETE FROM files WHERE id = $1", fileID)
			if err != nil {
				log.Printf("Error deleting file %s from database: %v", fileName, err)
				continue
			}

			// Clear the Redis cache
			claims := &Claims{} // Update with the correct user identification
			redisClient.Del(context.Background(), "files_"+claims.Email)

			log.Printf("Successfully deleted expired file: %s", fileName)
		}
	}
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket Upgrade Error:", err)
		return
	}
	defer conn.Close()

	// Register client
	clients[conn] = true
	defer func() {
		delete(clients, conn)
	}()

	// Keep connection alive, no specific message expected from the client
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Println("WebSocket Read Error:", err)
			break
		}
	}
}

func notifyFileUploadCompleted(fileName string) {
	message := fmt.Sprintf("File %s uploaded successfully", fileName)
	broadcast <- message
}

func handleBroadcast() {
	for {
		// Grab next message from the broadcast channel
		msg := <-broadcast

		// Send the message to every connected client
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				log.Printf("WebSocket Write Error: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}

// Encrypts the file content before uploading to S3
func encryptFile(content []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encryptedContent := gcm.Seal(nonce, nonce, content, nil)
	return encryptedContent, nil
}

// Decrypts the file content after downloading from S3
func decryptFile(encryptedContent []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedContent) < nonceSize {
		return nil, err
	}

	nonce, encryptedContent := encryptedContent[:nonceSize], encryptedContent[nonceSize:]
	decryptedContent, err := gcm.Open(nil, nonce, encryptedContent, nil)
	if err != nil {
		return nil, err
	}

	return decryptedContent, nil
}

// Initialize and return the router (for testing)
func initRouter() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/register", registerHandler).Methods("POST")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.Handle("/upload", jwtMiddleware(http.HandlerFunc(uploadFileHandler))).Methods("POST")
	router.Handle("/files", jwtMiddleware(http.HandlerFunc(getFilesHandler))).Methods("GET")
	router.Handle("/search", jwtMiddleware(http.HandlerFunc(searchFilesHandler))).Methods("GET")
	router.Handle("/share/{file_id}", jwtMiddleware(http.HandlerFunc(shareFileHandler))).Methods("GET")      // File sharing route
	router.Handle("/delete/{file_id}", jwtMiddleware(http.HandlerFunc(deleteFileHandler))).Methods("DELETE") // File delete route
	router.HandleFunc("/ws", wsHandler)

	return router
}

func main() {
	initDB()
	initRedis()

	go handleBroadcast()
	go deleteExpiredFiles() // Run the background worker in a separate goroutine

	router := initRouter()

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
