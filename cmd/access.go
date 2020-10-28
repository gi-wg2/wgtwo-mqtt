package main

import (
	"fmt"
	"log"
	"regexp"
)

type Access struct{}

func (a *Access) Authenticate(usernameBytes []byte, passwordbytes []byte) bool {
	username := string(usernameBytes)
	password := string(passwordbytes)

	if username == "admin" && password == AdminPassword {
		return true
	}

	u, ok := Users[username]
	if !ok {
		return false
	}
	match := u.password == password
	return match
}

func (a *Access) ACL(user []byte, topic string, write bool) bool {
	username := string(user)
	if username == "admin" {
		return true
	}

	pattern := fmt.Sprintf("^%s/", username)
	matched, err := regexp.MatchString(pattern, topic)
	if err != nil {
		log.Fatalln("ACL regex failed")
		return false
	}
	return matched
}
