package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// SSHConfig holds the configuration for SSH connection
type SSHConfig struct {
	User     string
	Password string
	KeyFile  string
	KeyPass  string
	Host     string
	Port     int
	Command  string
}

func main() {
	config := parseFlags()

	client, session, err := connect(config)
	if err != nil {
		log.Fatalf("Failed to connect: %s", err)
	}
	defer client.Close()
	defer session.Close()

	if config.Command == "" {
		startInteractiveSession(session)
	} else {
		output, err := runCommand(session, config.Command)
		if err != nil {
			log.Fatalf("Failed to run command: %s", err)
		}
		fmt.Println(output)
	}
}

func parseFlags() SSHConfig {
	var config SSHConfig
	flag.StringVar(&config.User, "user", "", "SSH username")
	flag.StringVar(&config.Password, "password", "", "SSH password")
	flag.StringVar(&config.KeyFile, "key", "", "Path to the private key file")
	flag.StringVar(&config.KeyPass, "keypass", "", "Password for the private key file")
	flag.StringVar(&config.Host, "host", "", "SSH host")
	flag.IntVar(&config.Port, "port", 22, "SSH port (default: 22)")
	flag.StringVar(&config.Command, "command", "", "Command to run on the remote host")
	flag.Parse()

	if config.User == "" || config.Host == "" {
		fmt.Println("Usage: ssh-client -user <user> -password <password> -key <key_file> -keypass <key_password> -host <host> -port <port> [-command <command>]")
		fmt.Println("You must provide either a password or a key file for authentication.")
		os.Exit(1)
	}

	if config.Password == "" && config.KeyFile == "" {
		fmt.Println("You must provide either a password or a key file for authentication.")
		os.Exit(1)
	}

	return config
}

func connect(config SSHConfig) (*ssh.Client, *ssh.Session, error) {
	var authMethods []ssh.AuthMethod

	if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	if config.KeyFile != "" {
		key, err := ioutil.ReadFile(config.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read private key: %v", err)
		}

		var signer ssh.Signer
		if config.KeyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(config.KeyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}

		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse private key: %v", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	clientConfig := &ssh.ClientConfig{
		User:            config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial: %s", err)
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %s", err)
	}

	return client, session, nil
}

func runCommand(session *ssh.Session, cmd string) (string, error) {
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	if err := session.Run(cmd); err != nil {
		return "", fmt.Errorf("failed to run: %s", err)
	}

	return stdoutBuf.String(), nil
}

func startInteractiveSession(session *ssh.Session) {
	defer session.Close()

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // Enable echoing
		ssh.TTY_OP_ISPEED: 14400, // Input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // Output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("request for pseudo terminal failed: %s", err)
	}

	// Set up stdin, stdout, and stderr
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Start remote shell
	if err := session.Shell(); err != nil {
		log.Fatalf("failed to start shell: %s", err)
	}

	// Handle interrupts to properly close the session
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range sigChan {
			session.Close()
			os.Exit(0)
		}
	}()

	if err := session.Wait(); err != nil {
		log.Fatalf("failed to wait for session: %s", err)
	}
}
