package main

import (
	"fmt"
	"log"
	"regexp"
)

type Access struct{}

func (a *Access) Authenticate(user []byte, password []byte) bool {
	username := string(user)
	log.Println("Username: " + username + " Password: " + string(password))

	u, ok := Users[username]
	if !ok {
		return false
	}
	match := u.password == string(password)
	log.Printf("Username=%s -> %t", username, match)
	return match
}

func (a *Access) ACL(user []byte, topic string, write bool) bool {
	username := string(user)
	if username == "admin" {
		return true
	}

	pattern := fmt.Sprintf("^%s/", username)
	matched, err := regexp.MatchString(pattern, topic)

	if write {
		log.Printf("[WRITE] match=%t Username=%s topic=%s", matched, username, topic)
	} else {
		log.Printf("[ READ] match=%t Username=%s topic=%s", matched, username, topic)
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
