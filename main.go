package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"strconv"
	"crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "os"

	"github.com/dgraph-io/badger/v3"
	"github.com/gorilla/mux"
	"github.com/google/uuid"

)

type Account struct {
    PublicKey  string `json:"publicKey"`
    PrivateKey string `json:"privateKey"`
}


// Transaction representa uma transação na blockchain
type Transaction struct {
    ID     string `json:"id"`
    From   string `json:"from"`
    To     string `json:"to"`
    Amount int    `json:"amount"`
}

// Block representa um bloco na blockchain
type Block struct {
	Index        int          `json:"index"`
	Timestamp    string       `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	Hash         string       `json:"hash"`
	PrevHash     string       `json:"prevHash"`
	Nonce        int          `json:"nonce"`
}

// Blockchain é uma lista encadeada de blocos
type Blockchain struct {
    Chain    []Block   `json:"chain"`
    mu       sync.Mutex
    Accounts []Account `json:"accounts"`
}

var blockchain Blockchain
var db *badger.DB
var once sync.Once
var PendingTransactions []Transaction
const Port = ":8080"
const AccountDBKey = "accounts"


// Saldo representa o saldo de uma conta na blockchain
type Saldo map[string]int

func createGenesisBlock() Block {
    // Preencha as informações do bloco genesis
    genesisBlock := Block{
        Index:        0,
        Timestamp:    time.Now().String(),
        Transactions: []Transaction{},
        PrevHash:     "",
        Hash:         "",
        Nonce:        0,
    }

    // Mine o bloco genesis
    genesisBlock.Nonce = mineBlock(genesisBlock.Index, genesisBlock.Timestamp, genesisBlock.PrevHash)
    genesisBlock.Hash = calculateHash(genesisBlock.Index, genesisBlock.Timestamp, genesisBlock.PrevHash, genesisBlock.Nonce)

    return genesisBlock
}

func AccountAddress(publicKey string) string {
    // Use SHA-256 para calcular o hash da chave pública
    hash := sha256.New()
    hash.Write([]byte(publicKey))
    addressBytes := hash.Sum(nil)

    // Converta o hash para uma representação hexadecimal
    address := hex.EncodeToString(addressBytes)

    return address
}


func generateUniqueTransactionID() string {
    id := uuid.New().String()
    return id
}

func generateKeyPair() (string, string, error) {
    // Gere um par de chaves RSA
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return "", "", err
    }

    // Codifique a chave privada em formato PEM
    privatePEM := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    }

    // Salve a chave privada em um arquivo (você pode ajustar conforme necessário)
    privateFile, err := os.Create("private.pem")
    if err != nil {
        return "", "", err
    }
    pem.Encode(privateFile, privatePEM)
    privateFile.Close()

    // Extrai a chave pública do par de chaves
    publicKey := &privateKey.PublicKey

    // Codifica a chave pública em formato PEM
    publicPEM := &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: x509.MarshalPKCS1PublicKey(publicKey),
    }

    // Salve a chave pública em um arquivo (você pode ajustar conforme necessário)
    publicFile, err := os.Create("public.pem")
    if err != nil {
        return "", "", err
    }
    pem.Encode(publicFile, publicPEM)
    publicFile.Close()

    // Retorne as representações em string das chaves
    return string(pem.EncodeToMemory(privatePEM)), string(pem.EncodeToMemory(publicPEM)), nil
}

func updateAccountsInDB(accounts []Account) error {
    return db.Update(func(txn *badger.Txn) error {
        encoded, err := json.Marshal(accounts)
        if err != nil {
            return fmt.Errorf("Erro ao codificar as contas para o BadgerDB: %v", err)
        }
        return txn.Set([]byte(AccountDBKey), encoded)
    })
}


func handleCreateAccount(w http.ResponseWriter, r *http.Request) {
    // Lógica para gerar novo par de chaves
    privateKey, publicKey, err := generateKeyPair()
    if err != nil {
        http.Error(w, "Erro ao gerar par de chaves", http.StatusInternalServerError)
        return
    }

    // Crie uma nova conta
    account := Account{
        PrivateKey: privateKey,
        PublicKey:  publicKey,
    }

    // Adicione a conta à lista de contas na blockchain
    bc := getBlockchain()
    bc.mu.Lock()
    defer bc.mu.Unlock()
    bc.Accounts = append(bc.Accounts, account)

    // Salve a lista de contas no BadgerDB
    err = updateAccountsInDB(bc.Accounts)
    if err != nil {
        http.Error(w, "Erro ao salvar a conta no BadgerDB", http.StatusInternalServerError)
        return
    }

    // Crie o endereço da conta usando a chave pública
    accountAddress := AccountAddress(publicKey)

    // Retorne a nova conta e o endereço como resposta
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(struct {
        Account      Account `json:"account"`
        AccountAddress string  `json:"accountAddress"`
    }{
        Account:      account,
        AccountAddress: accountAddress,
    })
}


// ConsultarSaldo retorna o saldo de uma conta na blockchain
func (bc *Blockchain) ConsultarSaldo(conta string) int {
	saldo := make(Saldo)

	bc.mu.Lock()
	defer bc.mu.Unlock()

	for _, bloco := range bc.Chain {
		for _, tx := range bloco.Transactions {
			// Atualizar saldo da conta de origem
			saldo[tx.From] -= tx.Amount
			// Atualizar saldo da conta de destino
			saldo[tx.To] += tx.Amount
		}
	}

	return saldo[conta]
}

// ConsultarSaldoAtéBloco retorna o saldo de uma conta até o bloco especificado
func (bc *Blockchain) ConsultarSaldoAtéBloco(conta string, index int) int {
	saldo := make(Saldo)

	bc.mu.Lock()
	defer bc.mu.Unlock()

	for i := 0; i <= index; i++ {
		for _, tx := range bc.Chain[i].Transactions {
			// Atualizar saldo da conta de origem
			saldo[tx.From] -= tx.Amount
			// Atualizar saldo da conta de destino
			saldo[tx.To] += tx.Amount
		}
	}

	return saldo[conta]
}

// Função para obter a instância da blockchain
func getBlockchain() *Blockchain {
	return &blockchain
}

func openDBOnce() error {
    var err error
    once.Do(func() {
        // Abra o BadgerDB
        opts := badger.DefaultOptions("badgerDB")
        opts.Logger = nil // Desativar logs internos para simplificar

        db, err = badger.Open(opts)
        if err != nil {
            log.Fatal("Erro ao abrir o BadgerDB:", err)
        }

        // Carregue a blockchain do BadgerDB apenas se existir
        err = db.View(func(txn *badger.Txn) error {
            // Carregar a blockchain
            item, err := txn.Get([]byte("blockchain"))
            if err != nil && err != badger.ErrKeyNotFound {
                return err
            }
            if item != nil {
                err = item.Value(func(val []byte) error {
                    return json.Unmarshal(val, &blockchain.Chain)
                })
                if err != nil {
                    return err
                }
            }

            // Carregar as contas
            item, err = txn.Get([]byte(AccountDBKey))
            if err != nil && err != badger.ErrKeyNotFound {
                return err
            }
            if item != nil {
                err = item.Value(func(val []byte) error {
                    return json.Unmarshal(val, &blockchain.Accounts)
                })
                if err != nil {
                    return err
                }
            }

            return nil
        })

        if err != nil {
            log.Fatal("Erro ao carregar a blockchain e as contas do BadgerDB:", err)
        }

        // Se a blockchain não existir no BadgerDB, crie o bloco genesis
        if len(blockchain.Chain) == 0 {
            genesisBlock := createGenesisBlock()
            blockchain.Chain = append(blockchain.Chain, genesisBlock)

            // Salve o bloco genesis no BadgerDB
            err = db.Update(func(txn *badger.Txn) error {
                encoded, err := json.Marshal(blockchain.Chain)
                if err != nil {
                    return err
                }
                return txn.Set([]byte("blockchain"), encoded)
            })
            if err != nil {
                log.Fatal("Erro ao salvar o bloco genesis no BadgerDB:", err)
            }
        }
    })

    return err
}


func closeDB(db *badger.DB) {
    err := db.Close()
    if err != nil {
        log.Fatal("Erro ao fechar o BadgerDB:", err)
    }
}

func calculateHash(index int, timestamp, prevHash string, nonce int) string {
	hashInput := fmt.Sprintf("%d%s%s%d", index, timestamp, prevHash, nonce)
	hashInBytes := sha256.Sum256([]byte(hashInput))
	return hex.EncodeToString(hashInBytes[:])
}

func handleGetAccounts(w http.ResponseWriter, r *http.Request) {
    // Obtenha a lista de contas da blockchain
    bc := getBlockchain()
    bc.mu.Lock()
    defer bc.mu.Unlock()
    accounts := bc.Accounts

    // Retorne a lista de contas como resposta
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(accounts)
}


func generateBlock(prevBlock Block, transactions []Transaction) Block {
    var newBlock Block

    newBlock.Index = prevBlock.Index + 1
    newBlock.Timestamp = time.Now().String()
    newBlock.Transactions = transactions
    newBlock.PrevHash = prevBlock.Hash

    // Inicie a mineração
    newBlock.Nonce = mineBlock(newBlock.Index, newBlock.Timestamp, newBlock.PrevHash)

    // Calcule o hash final
    newBlock.Hash = calculateHash(newBlock.Index, newBlock.Timestamp, newBlock.PrevHash, newBlock.Nonce)

    return newBlock
}


func simulateMining() {
    bc := getBlockchain()
    bc.mu.Lock()
    defer bc.mu.Unlock()

    // Simule transações pendentes (aqui, você pode adicionar lógica para obter transações pendentes da sua aplicação)
    transactions := PendingTransactions

    prevBlock := bc.Chain[len(bc.Chain)-1]
    newBlock := generateBlock(prevBlock, transactions)

    if isBlockValid(newBlock, prevBlock) {
        bc.Chain = append(bc.Chain, newBlock)
        fmt.Printf("Bloco adicionado à blockchain. Hash: %s\n", newBlock.Hash)

        // Atualize BadgerDB (se necessário)

        // Limpe as transações pendentes após adicionar o bloco
        PendingTransactions = []Transaction{}
    } else {
        fmt.Println("Erro ao validar o bloco. Bloco não adicionado à blockchain.")
    }
}

func mineBlock(index int, timestamp, prevHash string) int {
    nonce := 0
    for {
        hash := calculateHash(index, timestamp, prevHash, nonce)
        // Adapte o critério de prova de trabalho conforme necessário
        if strings.HasPrefix(hash, "0000") { // Número de zeros necessários
            return nonce
        }
        nonce++
    }
}


func isBlockValid(newBlock, prevBlock Block) bool {
	if prevBlock.Index+1 != newBlock.Index {
		return false
	}
	if prevBlock.Hash != newBlock.PrevHash {
		return false
	}
	if calculateHash(newBlock.Index, newBlock.Timestamp, newBlock.PrevHash, newBlock.Nonce) != newBlock.Hash {
		return false
	}
	return true
}

func validateTransaction(tx Transaction) bool {
    // Verificar assinatura digital da transação
    // ...

    // Verificar saldo da conta de origem
    bc := getBlockchain()
    bc.mu.Lock()
    defer bc.mu.Unlock()

    if bc.ConsultarSaldo(tx.From) < tx.Amount {
        return false
    }

    // Verificar outras condições, se necessário

    return true
}


func handleAddBlock(w http.ResponseWriter, r *http.Request) {
    bc := getBlockchain()
    bc.mu.Lock()
    defer bc.mu.Unlock()

    if len(PendingTransactions) == 0 {
        log.Println("Nenhuma transação pendente para adicionar ao bloco")
        http.Error(w, "Nenhuma transação pendente para adicionar ao bloco", http.StatusBadRequest)
        return
    }

    log.Printf("Transações pendentes antes de adicionar o bloco: %+v\n", PendingTransactions)

    var data struct {
        Transactions []Transaction `json:"transactions"`
    }
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&data); err != nil {
        log.Println("Erro ao decodificar o corpo da requisição:", err)
        http.Error(w, "Erro ao decodificar o corpo da requisição", http.StatusBadRequest)
        return
    }


    // Validar transações
    for _, tx := range data.Transactions {
        if !validateTransaction(tx) {
            log.Printf("Transação inválida: %+v\n", tx)
            http.Error(w, "Transação inválida", http.StatusBadRequest)
            return
        }
    }

    prevBlock := bc.Chain[len(bc.Chain)-1]
    newBlock := generateBlock(prevBlock, data.Transactions)

    if isBlockValid(newBlock, prevBlock) {
        // Atualizar a blockchain local
        bc.Chain = append(bc.Chain, newBlock)
        fmt.Printf("Bloco adicionado à blockchain. Hash: %s\n", newBlock.Hash)

        // Atualizar BadgerDB
        err := updateBlockchainInDB(bc.Chain)
        if err != nil {
            log.Println("Erro ao salvar a blockchain no BadgerDB:", err)
            http.Error(w, "Erro ao salvar a blockchain", http.StatusInternalServerError)
            return
        }

        // Limpar transações pendentes após adicionar o bloco
        PendingTransactions = []Transaction{}

        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(newBlock)
    } else {
        log.Printf("Erro ao validar o bloco. Bloco inválido: %+v\n", newBlock)
        http.Error(w, "Erro ao validar o bloco. Bloco não adicionado à blockchain.", http.StatusBadRequest)
    }
}



func updateBlockchainInDB(chain []Block) error {
    // Atualizar BadgerDB
    return db.Update(func(txn *badger.Txn) error {
        encoded, err := json.Marshal(chain)
        if err != nil {
            log.Println("Erro ao codificar a blockchain:", err)
            return err
        }
        if err := txn.Set([]byte("blockchain"), encoded); err != nil {
            log.Println("Erro ao salvar a blockchain no BadgerDB:", err)
            return err
        }
        log.Println("Blockchain atualizada no BadgerDB.")
        return nil
    })
}

func handleGetFirstBlock(w http.ResponseWriter, r *http.Request) {
	bc := getBlockchain()
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if len(bc.Chain) > 0 {
		firstBlock := bc.Chain[0]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(firstBlock)
	} else {
		http.Error(w, "A blockchain está vazia. Não há blocos para retornar.", http.StatusNotFound)
	}
}


func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bc := getBlockchain()
	bc.mu.Lock()
	defer bc.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bc.Chain)
}

func handleGetBlockBalance(w http.ResponseWriter, r *http.Request) {
	bc := getBlockchain()
	bc.mu.Lock()
	defer bc.mu.Unlock()

	vars := mux.Vars(r)
	conta := vars["conta"]
	index, err := strconv.Atoi(vars["index"])
	if err != nil {
		http.Error(w, "Índice inválido", http.StatusBadRequest)
		return
	}

	if index < 0 || index >= len(bc.Chain) {
		http.Error(w, "Índice fora dos limites", http.StatusBadRequest)
		return
	}

	balance := bc.ConsultarSaldoAtéBloco(conta, index)
	response := struct {
		Conta string `json:"conta"`
		Saldo int    `json:"saldo"`
		Bloco int    `json:"bloco"`
	}{
		Conta: conta,
		Saldo: balance,
		Bloco: index,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetTransaction(w http.ResponseWriter, r *http.Request) {
	bc := getBlockchain()
	bc.mu.Lock()
	defer bc.mu.Unlock()

	vars := mux.Vars(r)
	txID := vars["txID"]

	for _, bloco := range bc.Chain {
		for _, tx := range bloco.Transactions {
			if tx.ID == txID {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tx)
				return
			}
		}
	}

	http.Error(w, "Transação não encontrada", http.StatusNotFound)
}

func handleGetRealTimeBalance(w http.ResponseWriter, r *http.Request) {
	bc := getBlockchain()
	bc.mu.Lock()
	defer bc.mu.Unlock()

	vars := mux.Vars(r)
	conta := vars["conta"]

	balance := bc.ConsultarSaldo(conta)
	response := struct {
		Conta string `json:"conta"`
		Saldo int    `json:"saldo"`
	}{
		Conta: conta,
		Saldo: balance,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetPendingTransactions(w http.ResponseWriter, r *http.Request) {
	bc := getBlockchain()
	bc.mu.Lock()
	defer bc.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PendingTransactions)
}

func setupAPIRoutes(router *mux.Router) {
	router.HandleFunc("/addBlock", handleAddBlock).Methods("POST")
	router.HandleFunc("/getBlockchain", handleGetBlockchain).Methods("GET")
	router.HandleFunc("/getBlockBalance/{conta}/{index:[0-9]+}", handleGetBlockBalance).Methods("GET")
	router.HandleFunc("/getTransaction/{txID}", handleGetTransaction).Methods("GET")
	router.HandleFunc("/getRealTimeBalance/{conta}", handleGetRealTimeBalance).Methods("GET")
	router.HandleFunc("/getPendingTransactions", handleGetPendingTransactions).Methods("GET")
	router.HandleFunc("/getFirstBlock", handleGetFirstBlock).Methods("GET") 
	router.HandleFunc("/mine", handleMine).Methods("GET") 
	router.HandleFunc("/createAccount", handleCreateAccount).Methods("POST")
	router.HandleFunc("/getAccounts", handleGetAccounts).Methods("GET") 
	router.HandleFunc("/sendTransaction", handleSendTransaction).Methods("POST")
	// Adicione esta linha
	// Adicione esta linha para a rota de mineração
}

func startHTTPServer() {
	router := mux.NewRouter()
	setupAPIRoutes(router)

	// Inicie o servidor
	fmt.Println("Servidor ouvindo em", Port)
	if err := http.ListenAndServe(Port, router); err != nil {
		log.Fatal("Erro ao iniciar o servidor:", err)
	}
}

func handleMine(w http.ResponseWriter, r *http.Request) {
	bc := getBlockchain()
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Simule transações pendentes (você pode adicionar lógica para obter transações pendentes da sua aplicação)
	transactions := PendingTransactions

	prevBlock := bc.Chain[len(bc.Chain)-1]
	newBlock := generateBlock(prevBlock, transactions)

	if isBlockValid(newBlock, prevBlock) {
		bc.Chain = append(bc.Chain, newBlock)
		fmt.Printf("Bloco adicionado à blockchain. Hash: %s\n", newBlock.Hash)

		// Atualizar BadgerDB (se necessário)
		err := updateBlockchainInDB(bc.Chain)
		if err != nil {
			http.Error(w, "Erro ao salvar a blockchain no BadgerDB", http.StatusInternalServerError)
			return
		}

		// Limpar transações pendentes após adicionar o bloco
		PendingTransactions = []Transaction{}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newBlock)
	} else {
		http.Error(w, "Erro ao validar o bloco. Bloco não adicionado à blockchain.", http.StatusBadRequest)
	}
}

func handleSendTransaction(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Transactions []Transaction `json:"transactions"`
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&data); err != nil {
		http.Error(w, "Erro ao decodificar a transação", http.StatusBadRequest)
		return
	}

	// Atribuir IDs únicos às novas transações
	for i := range data.Transactions {
		data.Transactions[i].ID = uuid.New().String()
	}

	// Adicione as novas transações à lista de transações pendentes
	PendingTransactions = append(PendingTransactions, data.Transactions...)

	// Retorne a lista de transações pendentes como parte da resposta
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(struct {
		Transactions []Transaction `json:"transactions"`
	}{
		Transactions: data.Transactions,
	})
}


func loadBlockchainFromDB() error {
    // Abra o BadgerDB
    opts := badger.DefaultOptions("badgerDB")
    opts.Logger = nil // Desativar logs internos para simplificar

    db, err := badger.Open(opts)
    if err != nil {
        return fmt.Errorf("Erro ao abrir o BadgerDB: %v", err)
    }
    defer db.Close()

     // Carregue as contas do BadgerDB apenas se existirem
	 err = db.View(func(txn *badger.Txn) error {
        item, err := txn.Get([]byte(AccountDBKey))
        if err != nil && err != badger.ErrKeyNotFound {
            return fmt.Errorf("Erro ao obter as contas do BadgerDB: %v", err)
        }
        if item != nil {
            err = item.Value(func(val []byte) error {
                return json.Unmarshal(val, &blockchain.Accounts)
            })
            if err != nil {
                return fmt.Errorf("Erro ao decodificar as contas do BadgerDB: %v", err)
            }
        }
        return nil
    })
    if err != nil {
        return err
    }

    // Se a blockchain não existir no BadgerDB, crie o bloco genesis
    if len(blockchain.Chain) == 0 {
        genesisBlock := createGenesisBlock()
        blockchain.Chain = append(blockchain.Chain, genesisBlock)

        // Salve o bloco genesis no BadgerDB
        err = db.Update(func(txn *badger.Txn) error {
            encoded, err := json.Marshal(blockchain.Chain)
            if err != nil {
                return fmt.Errorf("Erro ao codificar a blockchain para o BadgerDB: %v", err)
            }
            return txn.Set([]byte("blockchain"), encoded)
        })
        if err != nil {
            return fmt.Errorf("Erro ao salvar o bloco genesis no BadgerDB: %v", err)
        }
    }

    return nil
}

func main() {
    // Carregue a blockchain do BadgerDB ao iniciar o programa
    if err := openDBOnce(); err != nil {
        log.Fatal("Erro ao abrir o BadgerDB:", err)
    }

    // Se a blockchain ainda não foi carregada, crie o bloco genesis
    if len(blockchain.Chain) == 0 {
        genesisBlock := createGenesisBlock()
        blockchain.Chain = append(blockchain.Chain, genesisBlock)

        // Salve o bloco genesis no BadgerDB
        err := updateBlockchainInDB(blockchain.Chain)
        if err != nil {
            log.Fatal("Erro ao salvar o bloco genesis no BadgerDB:", err)
        }
    }

    // Inicie o servidor HTTP
    startHTTPServer()

    // Feche o BadgerDB ao encerrar o programa (dentro de um bloco defer)
    defer func() {
        if err := db.Close(); err != nil {
            log.Fatal("Erro ao fechar o BadgerDB:", err)
        }
    }()
}
