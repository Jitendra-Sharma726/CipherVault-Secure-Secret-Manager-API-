package main

import (
  "encoding/json"
  "fmt"
  "net/http"
  "strings"
  "sync"
  "time"

  "github.com/golang-jwt/jwt/v5"
  "golang.org/x/crypto/bcrypt"
)

// --- 1.DATA MODELS AND GLOBALS

type Credentials struct {
  Username string `json:"username"`
  Password string `json:"password"`
}

type User struct {
 Username  string
 PasswordHash  []byte
}

//TokenBlacklist safely stores invalidated tokens using a Read-Write Mutex
type TokenBlacklist struct {
  tokens map[string]bool
  mu   sync.RWMutex
}

var (
  //Secret key for JWT signing (In production, load this from .env file)
  jwtKey = []byte("f4a8b7e2c9d1f3a6b5e8c7d4a1f9e2b3"

  // mockDB simulates a database table for users
  mockDB = make(map[string]User)

 //blacklist instance
 blacklist = TokenBlacklist{
       tokens: make(map[string]bool),
   }
)

// --- 2.  ENTRY POINT --- 

func main() {
  //1. Public API routes
  http.HandleFunc("/register", RegisterHandler
  http.HandlerFunc("/login", LoginHandler)

 //2.Protected API routes (Wrapped in Auth Middleware)
  http.HandleFunc("/secret", authMiddleware(SecretHandler))
  http.HandleFunc("/logout", authMiddleware(LogoutHandler))

  fmt.Println(" Server running on port 8080")

  // Start the server
  err := http.ListenAndServe(":8080", nil)
  if err != nil {
      fmt.Printf("Server crashed : %v\n", err)
  }
}

//--- 3. BLACKLIST LOGIC (MUTEX) ---

//Add safely inserts a token into the blacklist using a Write Lock.
func (b *TokenBlacklist) Add(token string) {
  b.mu.Lock()
  defer b.mu.Unlock()
  b.tokens[token] = true
}

//Contains Safely checks if a token is blacklisted using a Read Lock.
func (b *TokenBlacklist) Contains(token string) bool {
  b.mu.RLock()
  defer b.mu.RUnlock()
  return b.tokens[token]
                  

//--- 4. ROUTE HANDLERS ---
//RegisterHandler accepts a username and password, hashes the password and stores it.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != http.MethodPost {
    http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    return
  }

 var creds Credentials
 decoder := json.NewDecoder(r.Body)
 err := decoder.Decode(&creds)

 if err != nil {
     http.Error(w, "Invalid request payload", http.StatusBadRequest)
     return
  }

  _, exists := mockDB[creds.Username]
  if exists {
    http.Error(w, "User already exists", http.StatusConflict)
    return
  }

  //Hash the password
  hashedPaasword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
  if err != nil {
      http.Error(w, "Internal server error", http.StatusInternalServerError)
      return
  }

  //Store User
  mockDB[creds.Username] = User{
    Username: creds.Username,
    PasswordHash: hashedPassword,
  }

  //Send Successful response
  w.Header().Set("Content-Type", "application/json")
  w.WriteHeader(http.StatusCreated)

  message := map[string]string{
       "message": "User registered successfully",
  }
  responseBytes, _ := json.Marshal(message)
  w.Write(responseBytes)
}
  
//LoginHandler verifies credentials and issues a JWT.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != http.MethodPost {
      http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
      return
  }

  var creds Credentials
  decoder := json.NewDecoder(r.Body)
  err := decoder.Decode(&creds)


  if err != nil {
    http.Error(w, "Invalid request payload", http.StatusBadRequest)
    return 
  }

  User, exists := mockDB[creds.Username]
  if !exists {
    http.Error(w, "Invalid username or password", http.StatusUnauthorized)
    return
  }

  err = bcrypt.CompareHashAndPassword(users.PasswordHash, []byte(creds.Password))
  if err != nil {
    http.Error(w, "Invalid username or password", http.StatusUnauthorized)
    return
  }

  //Generate the JWT token
  token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "username" : creds.Username,
        "exp":       time.Now().Add(1 * time.Hour).Unix(),
    })

  tokenString, err := token.SignedString(jwtKey)
  if err != nil {
    http.Error(w, "Internal server error", http.StatusInternalServerError)
    return
  }

  //send the token back
  w.Header().Set("Content-Type", "application/json")
  responseData := map[string]string{
    "token" : tokenString,
  }
  responseBytes, _ := json.Marshal(responseData)
  w.Write(responseBytes)
}

//SecretHandler returns a top-secret payload (only accessible if authenticated).
func SecretHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")

  message := map[string]string{
    "message" : "CodeChef Contest Server: Hidden testcase archieve unlocked.",
  }
  responseBytes, _ :=json.Marshal(message)
  w.Write(responseBytes)
}

//LogoutHandler extracts the current token and adds it to the blacklist.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
  authHeader := r.Header.Get("Authorization")
  tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

  blacklist.Add(tokenStr)

  w.Header().Set("Content-Type", "application/json")
  responseData := map[string]string{
       "message": "Successfully logged out",
  }
  responseBytes, _ :=json.Marshal(responseData)
  w.Write(responseBytes)
}


// ---5. SECURITY MIDDLEWARE ---
//authMiddleware intercepts incoming requests, validates the JWT, and checks the blacklist.

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r*http.Request) {
    authHeader := r.Header.Get("Authorization")
    if authHeader == ""{
      http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
      return
    }

    //Extract the Token
    tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

    //check the Blacklist
    if blacklist.Contains(tokenStr) {
      http.Error(w, "Token has been invalidated (Logged out)", http.StatusUnauthorized)
      return
      }
    
    //Parse and validate the token signature
    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
      _, ok := token.Method(*jwt.SigningMethodHMAC)


      if !ok {
        return nil, fmt.Errorf("unexpected signing method")
      }
      return jwtKey, nil
    })

    if err != nil || !token.Valid {
      http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
      return
    }

    //Token is valid. Pass the request to the actual handler.
    next(w, r)
  }

}
  



      
    













  















  

  















  



















  
















  
  












                 
  
                  
  













      
