package main

import (
	"fmt"
	"log"
	"regexp"
)

type Access struct{}

func (a *Access) Authenticate(user []byte, password []byte) bool {
	log.Println("Username: " + string(user) + " Password: " + string(password))
	return true
}

func (a *Access) ACL(user []byte, topic string, write bool) bool {
	username := string(user)
	if username == "admin" {
		return true
	}

	pattern := fmt.Sprintf("^%s/", username)
	matched, err := regexp.MatchString(pattern, topic)

	if write {
		log.Printf("[WRITE] match=%t username=%s topic=%s", matched, username, topic)
	} else {
		log.Printf("[ READ] match=%t username=%s topic=%s", matched, username, topic)
	}

	if !matched {
		log.Println("No match")
		return false
	}
	if err != nil {
		log.Fatalln("ACL regex failed")
	}
	return true
}
