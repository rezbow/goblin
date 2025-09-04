package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/peterh/liner"
)

type Vault map[string]string

func NewVault() Vault {
	return make(Vault)
}

func (v Vault) ForEach(do func(string, string)) {
	for label, password := range v {
		do(label, password)
	}
}

func (v Vault) Get(label string) (string, bool) {
	pass, ok := v[label]
	return pass, ok
}

func (v Vault) Add(label, password string) {
	v[label] = password
}

func (v Vault) Delete(label string) error {
	_, ok := v[label]
	if !ok {
		return errors.New("label not in vault")
	}
	delete(v, label)
	return nil
}

func random(length int) ([]byte, error) {
	r := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (v Vault) Encrypt(pass []byte) ([]byte, error) {
	var result []byte
	salt, err := random(16)
	if err != nil {
		return nil, err
	}
	key := deriveKey(pass, salt)
	nonce, err := random(12)
	if err != nil {
		return nil, err
	}
	ciphertext, err := encrypt([]byte(v.ToString()), key, nonce)
	if err != nil {
		return nil, err
	}
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, err
}

func (v Vault) ToString() string {
	var builder strings.Builder
	for label, pass := range v {
		line := fmt.Sprintf("%s %s\n", label, pass)
		builder.WriteString(line)
	}
	return builder.String()
}

func WriteToFile(data []byte, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return err
}

func (v Vault) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	for label, pass := range v {
		line := fmt.Sprintf("%s %s\n", label, pass)
		_, err := writer.WriteString(line)
		if err != nil {
			return err
		}
	}
	err = writer.Flush()
	if err != nil {
		return err
	}
	return nil
}

func VaultFromReader(r io.Reader, pass string) (Vault, error) {
	vault := NewVault()
	storage, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(storage) < 28 {
		return nil, errors.New("storage invalid")
	}

	salt := storage[:16]
	nonce := storage[16 : 16+12]
	ciphertext := storage[16+12:]
	key := deriveKey([]byte(pass), salt)

	plaintext, err := decrypt(ciphertext, key, nonce)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(plaintext))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			return nil, errors.New("malformed line")
		}
		vault.Add(parts[0], parts[1])
	}
	return vault, nil
}

func VaultFromFile(path, pass string) (Vault, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return VaultFromReader(file, pass)
}

var EXIT = errors.New("exit command")

func (r *Repl) runCommand(line string) error {
	// ADD LABEL PASSWORD
	// DELETE LABEL
	// EXIT
	// SAVE filepath
	parts := strings.Split(line, " ")
	if len(parts) < 1 {
		return errors.New("invalid command")
	}
	switch strings.ToLower(parts[0]) {
	case "add":
		if len(parts) != 3 {
			return errors.New("missing arguments: ADD LABEL PASSWORD")
		}
		label := strings.TrimSpace(parts[1])
		pass := strings.TrimSpace(parts[2])
		r.vault.Add(label, pass)
	case "delete":
		if len(parts) != 2 {
			return errors.New("missing argument: DELETE LABEL")
		}
		return r.vault.Delete(parts[1])
	case "save":
		if len(parts) > 2 {
			return errors.New("Usage: SAVE FILEPATH")
		}
		path := r.vaultPath
		if len(parts) == 2 {
			path = parts[1]
		}
		data, err := r.vault.Encrypt([]byte(r.password))
		if err != nil {
			return err
		}
		WriteToFile(data, path)
	case "show":
		if len(parts) == 1 {
			r.vault.ForEach(func(label, pass string) {
				fmt.Printf("%s: %s\n", label, pass)
			})
			return nil
		}
		pass, ok := r.vault.Get(parts[1])
		if !ok {
			fmt.Println("label not found")
			return nil
		}
		fmt.Printf("%s: %s\n", parts[1], pass)

	case "exit":
		return EXIT
	default:
		return errors.New("unknown command")
	}
	return nil
}

func NewPrompter() *liner.State {
	prompter := liner.NewLiner()
	prompter.SetCtrlCAborts(true)

	commands := []string{"ADD", "DELETE", "SHOW", "SAVE", "EXIT"}
	prompter.SetCompleter(func(line string) (c []string) {

		for _, command := range commands {
			if strings.HasPrefix(strings.ToLower(command), strings.ToLower(line)) {
				c = append(c, command)
			}
		}
		return
	})

	prompter.SetBeep(false)

	prompter.SetTabCompletionStyle(liner.TabCircular)

	return prompter
}

type Repl struct {
	prompt    *liner.State
	vault     Vault
	vaultPath string
	password  string
}

func (r *Repl) Run() {
	defer r.prompt.Close()
	for {
		input, err := r.prompt.Prompt("> ")
		if err != nil {
			fmt.Println(err.Error())
			break
		}
		line := strings.TrimSpace(input)
		if line == "" {
			continue
		}
		err = r.runCommand(line)
		r.prompt.AppendHistory(line)
		if err != nil {
			if err == EXIT {
				fmt.Println("Exiting...")
				break
			}
			fmt.Println(err.Error())
			continue
		}
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: passly command argumnets")
		return
	}

	repl := &Repl{
		prompt:    NewPrompter(),
		vaultPath: os.Args[2],
	}
	switch os.Args[1] {
	case "create":
		pass, err := repl.prompt.PasswordPrompt("Password: ")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		repl.password = pass
		repl.vault = NewVault()
		repl.Run()
	case "open":
		pass, err := repl.prompt.PasswordPrompt("Password: ")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		v, err := VaultFromFile(os.Args[2], pass)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		repl.password = pass
		repl.vault = v
		repl.Run()
	default:
		fmt.Println("Unknown command!")
		return
	}
}
