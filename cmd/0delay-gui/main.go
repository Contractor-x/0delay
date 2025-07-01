package main

import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "sync"

    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/dialog"
    "fyne.io/fyne/v2/widget"
    "golang.org/x/crypto/pbkdf2"
    "github.com/joho/godotenv"
)

import (
    "encoding/json"
    "os"
    "path/filepath"
    "github.com/joho/godotenv"
    // other imports remain unchanged
)

const (
    listenPort = 9000
)

var configFilePath string

func init() {
    // Determine config file path relative to project root
    exePath, err := os.Executable()
    if err != nil {
        log.Fatalf("Failed to get executable path: %v", err)
    }
    projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(exePath)))
    configFilePath = filepath.Join(projectRoot, "configs", "config.json")
}

type Config struct {
    SupabaseURL    string            `json:"supabase_url"`
    SupabaseAnonKey string           `json:"supabase_anon_key"`
    PemKeys        map[string]string `json:"pem_keys"`
    TransferHistory []string         `json:"transfer_history"`
    LastTarget     string            `json:"last_target"`
}

func loadConfig() (*Config, error) {
    file, err := os.Open(configFilePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    var config Config
    decoder := json.NewDecoder(file)
    err = decoder.Decode(&config)
    if err != nil {
        return nil, err
    }
    return &config, nil
}

func saveConfig(config *Config) error {
    file, err := os.Create(configFilePath)
    if err != nil {
        return err
    }
    defer file.Close()
    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    return encoder.Encode(config)
}

func encrypt(data []byte, password string) ([]byte, error) {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, err
    }
    key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, aesgcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    ciphertext := aesgcm.Seal(nil, nonce, data, nil)
    return append(salt, append(nonce, ciphertext...)...), nil
}

func decrypt(data []byte, password string) ([]byte, error) {
    if len(data) < 16 {
        return nil, fmt.Errorf("data too short")
    }
    salt := data[:16]
    key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := aesgcm.NonceSize()
    if len(data) < 16+nonceSize {
        return nil, fmt.Errorf("data too short")
    }
    nonce := data[16 : 16+nonceSize]
    ciphertext := data[16+nonceSize:]
    return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func handleIncomingTransfer(w fyne.Window, transfer IncomingTransfer, wg *sync.WaitGroup) {
    defer wg.Done()
    reader := bufio.NewReader(transfer.Conn)

    // Read password prompt
    passwordPrompt := make([]byte, 1)
    _, err := io.ReadFull(reader, passwordPrompt)
    if err != nil {
        log.Println("Failed to read password prompt:", err)
        transfer.Conn.Close()
        return
    }
    // For simplicity, assume password prompt byte is 1 if password required, 0 otherwise
    passwordRequired := passwordPrompt[0] == 1

    var password string
    if passwordRequired {
        done := make(chan struct{})
        var accepted bool
        fyne.CurrentApp().SendNotification(&fyne.Notification{
            Title:   "Incoming File Transfer",
            Content: fmt.Sprintf("Incoming file transfer: %s. Accept?", transfer.FileName),
        })
        dialog.ShowConfirm(fmt.Sprintf("Incoming file: %s", transfer.FileName), "Accept file transfer?", func(confirm bool) {
            accepted = confirm
            close(done)
        }, w)
        <-done
        if !accepted {
            transfer.Conn.Close()
            return
        }
        // Prompt for password
        pwdEntry := widget.NewPasswordEntry()
        pwdEntry.SetPlaceHolder("Enter password")
        pwdDialog := dialog.NewCustomConfirm("Password Required", "OK", "Cancel", pwdEntry, func(confirm bool) {
            if confirm {
                password = pwdEntry.Text
            } else {
                transfer.Conn.Close()
            }
        }, w)
        pwdDialog.Show()
        // Wait for password dialog to close
        <-done
    }

    // Receive file size
    sizeBuf := make([]byte, 8)
    _, err = io.ReadFull(reader, sizeBuf)
    if err != nil {
        log.Println("Failed to read file size:", err)
        transfer.Conn.Close()
        return
    }
    fileSize := int64(binary.BigEndian.Uint64(sizeBuf))

    // Receive file data
    fileData := make([]byte, fileSize)
    _, err = io.ReadFull(reader, fileData)
    if err != nil {
        log.Println("Failed to read file data:", err)
        transfer.Conn.Close()
        return
    }

    if passwordRequired {
        fileData, err = decrypt(fileData, password)
        if err != nil {
            log.Println("Failed to decrypt file:", err)
            transfer.Conn.Close()
            return
        }
    }

    // Save file
    savePath := filepath.Join(".", transfer.FileName)
    err = os.WriteFile(savePath, fileData, 0644)
    if err != nil {
        log.Println("Failed to save file:", err)
        transfer.Conn.Close()
        return
    }

    dialog.ShowInformation("File Received", fmt.Sprintf("File %s received and saved.", transfer.FileName), w)
    transfer.Conn.Close()
}

func startListener(w fyne.Window, wg *sync.WaitGroup) {
    defer wg.Done()
    ln, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
    if err != nil {
        log.Println("Failed to start listener:", err)
        return
    }
    log.Println("Listening for incoming transfers on port", listenPort)
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println("Failed to accept connection:", err)
            continue
        }
        // For simplicity, read file name length and name
        go func(c net.Conn) {
            reader := bufio.NewReader(c)
            nameLenBuf := make([]byte, 2)
            _, err := io.ReadFull(reader, nameLenBuf)
            if err != nil {
                log.Println("Failed to read file name length:", err)
                c.Close()
                return
            }
            nameLen := int(binary.BigEndian.Uint16(nameLenBuf))
            nameBuf := make([]byte, nameLen)
            _, err = io.ReadFull(reader, nameBuf)
            if err != nil {
                log.Println("Failed to read file name:", err)
                c.Close()
                return
            }
            fileName := string(nameBuf)
            // For simplicity, assume file size next
            sizeBuf := make([]byte, 8)
            _, err = io.ReadFull(reader, sizeBuf)
            if err != nil {
                log.Println("Failed to read file size:", err)
                c.Close()
                return
            }
            fileSize := int64(binary.BigEndian.Uint64(sizeBuf))
            transfer := IncomingTransfer{
                Conn:     c,
                FileName: fileName,
                FileSize: fileSize,
            }
            var wgInner sync.WaitGroup
            wgInner.Add(1)
            go handleIncomingTransfer(w, transfer, &wgInner)
            wgInner.Wait()
        }(conn)
    }
}

func main() {
    // Load environment variables from .env file
    err := godotenv.Load("../../configs/.env")
    if err != nil {
        log.Println("Error loading .env file:", err)
    }


func registerUsername(supabaseURL, anonKey, username, ip string) error {
    type UserRecord struct {
        Username string `json:"username"`
        IP       string `json:"ip"`
    }
    user := UserRecord{
        Username: username,
        IP:       ip,
    }
    jsonData, err := json.Marshal(user)
    if err != nil {
        return err
    }
    req, err := http.NewRequest("POST", supabaseURL+"/rest/v1/usernames", bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }
    req.Header.Set("apikey", anonKey)
    req.Header.Set("Authorization", "Bearer "+anonKey)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Prefer", "return=representation")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 201 {
        bodyBytes, _ := ioutil.ReadAll(resp.Body)
        return fmt.Errorf("Supabase error: %s", string(bodyBytes))
    }
    return nil
}
