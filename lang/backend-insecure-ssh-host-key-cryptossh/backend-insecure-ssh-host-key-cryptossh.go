package main

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func bad01() {
	auth := ssh.Password("s4Cr4t")
	_ = &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{auth},
		// ruleid: backend-insecure-ssh-host-key-cryptossh
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func bad02() {
	auth := ssh.Password("s4Cr4t")
	callback := ssh.InsecureIgnoreHostKey()
	_ = &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{auth},
		// ruleid: backend-insecure-ssh-host-key-cryptossh
		HostKeyCallback: callback,
	}
}

func ok01() {
	// ok: backend-insecure-ssh-host-key-cryptossh
	_ = ssh.InsecureIgnoreHostKey()
	// ok: backend-insecure-ssh-host-key-cryptossh
	ssh.InsecureIgnoreHostKey()
}

func ok02() {
	auth := ssh.Password("s4Cr4t")
	knownHostCallback, err := knownhosts.New("~/.ssh/known_hosts")
	if err != nil {
		panic(err)
	}
	_ = &ssh.ClientConfig{
		User: "vhs",
		Auth: []ssh.AuthMethod{auth},
		// ok: backend-insecure-ssh-host-key-cryptossh
		HostKeyCallback: knownHostCallback,
	}
}
