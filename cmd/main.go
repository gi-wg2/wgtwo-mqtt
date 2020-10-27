package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/gi-wg2/wgtwo-mqtt/intern/oauth/wgtwo"
	"golang.org/x/oauth2/clientcredentials"
	"strings"

	//pb "github.com/gi-wg2/wgtwo-mqtt/intern/proto"
	//"github.com/golang/protobuf/ptypes"
	//"github.com/google/uuid"
	"github.com/logrusorgru/aurora"
	"github.com/markbates/goth"
	//"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth/gothic"
	mqtt "github.com/mochi-co/mqtt/server"
	"github.com/mochi-co/mqtt/server/listeners"
)

type User struct {
	password string
}

var Users = make(map[string]User)

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var AdminPassword = StringWithCharset(128, charset)

func getProviderName(*http.Request) (string, error) {
	return "wgtwo", nil
}

func login(w http.ResponseWriter, req *http.Request) {
	gothic.GetProviderName = getProviderName
	if user, err := gothic.CompleteUserAuth(w, req); err == nil {
		log.Println("Already logged in: " + user.UserID)
	} else {
		gothic.BeginAuthHandler(w, req)
	}
}

func callback(w http.ResponseWriter, req *http.Request) {
	user, err := gothic.CompleteUserAuth(w, req)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}

	key := strings.Replace(user.UserID, "+", "", 1)
	u := User{password: StringWithCharset(32, charset)}
	Users[key] = u
	_, _ = w.Write([]byte("Connect to MQTT: username=" + key + " password=" + u.password))
}

func main() {
	var tcpAddr = flag.String("tcp", ":1883", "network address for TCP listener")
	var infoAddr = flag.String("info", ":8080", "network address for web info dashboard listener")
	var clientId = flag.String("client-id", "", "")
	var clientSecret = flag.String("client-secret", "", "")
	var redirectUrl = flag.String("redirect-url", "", "")
	flag.Parse()

	if *redirectUrl == "" {
		log.Fatalln("--redirect-url cannot be null")
	}

	key := "Secret-session-key"  // Replace with your SESSION_SECRET or similar
	maxAge := 86400 * 30  // 30 days
	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = false

	gothic.Store = store
	goth.UseProviders(
		wgtwo.New(*clientId, *clientSecret, *redirectUrl, "phone", "offline_access", "events.voice.subscribe"),
	)

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()

	fmt.Println(aurora.Magenta("Mochi MQTT Broker initializing..."))
	fmt.Println(aurora.Cyan("TCP"), *tcpAddr)
	fmt.Println(aurora.Cyan("$SYS Dashboard"), *infoAddr)

	clientCredentialsConfig := &clientcredentials.Config{
		ClientID:     *clientId,
		ClientSecret: *clientSecret,
		Scopes: []string{
			"events.voice.subscribe",
		},
		TokenURL: wgtwo.Endpoint.TokenURL,
	}


	token, err := clientCredentialsConfig.Token(context.Background())
	if err != nil {
		panic(err)
	}
	log.Println("Token: " + token.AccessToken)

/*
	//tokenSource := clienCredentialsConfig.TokenSource(context.Background())
	conn, err := grpc.Dial(
		"api.wgtwo.com:443",
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

 */
	/*

	c := pb.NewEventsServiceClient(conn)
	ctx, kancel := context.WithTimeout(context.Background(), time.Second)
	defer kancel()

	eventTimeout, err := time.ParseDuration("10s")
	if err != nil {
		log.Panicln("Could not parse timeout")
	}

	r, err := c.Subscribe(ctx, &pb.SubscribeEventsRequest{
		Type:          []pb.EventType{pb.EventType_VOICE_EVENT},
		StartPosition: &pb.SubscribeEventsRequest_StartAtOldestPossible{},
		ClientId:      uuid.New().String(),
		QueueName:     "wgtwo-mqtt",
		DurableName:   "wgtwo-mqtt",
		MaxInFlight:   10,
		ManualAck: &pb.ManualAckConfig{
			Enable:  true,
			Timeout: ptypes.DurationProto(eventTimeout),
		},
	})
	if err != nil {
		log.Panicln("Error while fetching events")
	}
	for {
		event, err := r.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalln("Could not get event", err)
		}
		log.Println(event)
	}

	 */

	http.HandleFunc("/oauth/callback", callback)
	http.HandleFunc("/", login)

	log.Println("XXXXXXXXXXXXXXx")

	httpServer := &http.Server{Addr: ":9099"}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			_ = httpServer.Close()
			done <- true
		}
	}()

	server := mqtt.New()
	tcp := listeners.NewTCP("t1", *tcpAddr)
	err = server.AddListener(tcp, &listeners.Config{
		Auth: new(Access),
	})
	if err != nil {
		log.Fatal(err)
	}

	stats := listeners.NewHTTPStats("stats", *infoAddr)
	err = server.AddListener(stats, nil)
	if err != nil {
		log.Fatal(err)
	}

	go http.ListenAndServe(":9099", nil)
	go server.Serve()
	fmt.Println(aurora.BgMagenta("  Started!  "))

	<-done
	fmt.Println(aurora.BgRed("  Caught Signal  "))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalln("Could not shut down")
	}
	httpServer.Close()
	server.Close()
	fmt.Println(aurora.BgGreen("  Finished  "))
}
