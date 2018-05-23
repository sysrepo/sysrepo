package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/BurntSushi/toml"
	"github.com/sartura/go-netconf/netconf"
)

type config struct {
	Login login
	Test  []test
}

type login struct {
	Address  string
	Username string
	Password string
}

type test struct {
	XMLRequest  string
	XMLResponse string
}

func parseConfig(configFile string) {

	fmt.Printf("Parsing config file: %s\n", configFile)

	var Config config
	_, err := toml.DecodeFile(configFile, &Config)
	if err != nil {
		fmt.Printf("Toml error: %v\n", err)
		os.Exit(1)
	}

	auth := &ssh.ClientConfig{
		Config: ssh.Config{
			Ciphers: []string{"aes128-cbc", "hmac-sha1"},
		},
		User:            Config.Login.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(Config.Login.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	s, err := netconf.DialSSH(Config.Login.Address, auth)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	for i := range Config.Test {
		cfg := Config.Test[i]

		reply, err := s.Exec(netconf.RawMethod(cfg.XMLRequest))
		if err != nil {
			fmt.Printf("ERROR: %s\n", err)
			fmt.Printf("Fail for test %d\n", i)
			fmt.Printf("XMLRequest:\n%s\n", cfg.XMLRequest)
		}
		if cfg.XMLResponse != "" && reply.Data != cfg.XMLResponse {
			fmt.Printf("MISMATCH!\nEXPECTED: \n%s\nGOT: \n%s\n", cfg.XMLResponse, reply.Data)
		} else {
			fmt.Printf("Sucess for test %d\n", i)
		}
	}
}

func main() {

	dir := "./config/"

	files, _ := ioutil.ReadDir(dir)
	for _, file := range files {
		parseConfig(dir + file.Name())
	}
}
