package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"

    "github.com/joho/godotenv"
)

func main() {
    // Load environment variables from .env file
    err := godotenv.Load("../../configs/.env")
    if err != nil {
        log.Println("Error loading .env file:", err)
    }

    supabaseURL := os.Getenv("SUPABASE_URL")
    supabaseAnonKey := os.Getenv("SUPABASE_ANON_KEY")

    if supabaseURL == "" || supabaseAnonKey == "" {
        log.Fatal("Supabase URL or Anon Key not set in environment variables")
    }

    // Example admin functionality: list all usernames
    usernames, err := listUsernames(supabaseURL, supabaseAnonKey)
    if err != nil {
        log.Fatalf("Failed to list usernames: %v", err)
    }

    fmt.Println("Registered Usernames:")
    for _, user := range usernames {
        fmt.Printf("Username: %s, IP: %s\n", user.Username, user.IP)
    }
}

type UserRecord struct {
    Username string `json:"username"`
    IP       string `json:"ip"`
}

func listUsernames(supabaseURL, anonKey string) ([]UserRecord, error) {
    req, err := http.NewRequest("GET", supabaseURL+"/rest/v1/usernames", nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("apikey", anonKey)
    req.Header.Set("Authorization", "Bearer "+anonKey)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        bodyBytes, _ := ioutil.ReadAll(resp.Body)
        return nil, fmt.Errorf("Supabase error: %s", string(bodyBytes))
    }

    var users []UserRecord
    decoder := json.NewDecoder(resp.Body)
    err = decoder.Decode(&users)
    if err != nil {
        return nil, err
    }
    return users, nil
}
