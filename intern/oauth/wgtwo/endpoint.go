package wgtwo

import "golang.org/x/oauth2"

var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://id.wgtwo.com/oauth2/auth",
	TokenURL: "https://id.wgtwo.com/oauth2/token",
}
