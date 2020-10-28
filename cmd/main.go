package main

import (
	"context"
	"flag"
	"fmt"
	mqttc "github.com/eclipse/paho.mqtt.golang"
	"github.com/gi-wg2/wgtwo-mqtt/intern"
	"github.com/gi-wg2/wgtwo-mqtt/intern/oauth/wgtwo"
	pb "github.com/gi-wg2/wgtwo-mqtt/intern/proto"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/logrusorgru/aurora"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	mqtt "github.com/mochi-co/mqtt/server"
	"github.com/mochi-co/mqtt/server/listeners"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/status"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type User struct {
	password string
}

type Template struct {
	Username string
	Password string
}

var AdminPassword = intern.RandomAlphanumeric(128)

var Users = make(map[string]User)

const MaxUint = ^uint(0)

func index(w http.ResponseWriter, req *http.Request) {
	s, _ := store.Get(req, "mqtt")
	if userId, ok := s.Values["user-id"]; ok {
		msisdn := userId.(string)
		if u, ok := Users[msisdn]; ok {
			userinfo := Template{Username: msisdn, Password: u.password}
			t, _ := template.ParseFiles("templates/success.html")
			t.Execute(w, userinfo)
			return
		}
	}
	t, _ := template.ParseFiles("templates/login.html")
	t.Execute(w, nil)
}

func login(w http.ResponseWriter, req *http.Request) {
	gothic.GetProviderName = wgtwo.GetProviderName
	gothic.BeginAuthHandler(w, req)
}

func callback(w http.ResponseWriter, req *http.Request) {
	user, err := gothic.CompleteUserAuth(w, req)
	if err != nil {
		log.Println("Issue while completing OAuth flow", err)
	} else {
		key := strings.Replace(user.UserID, "+", "", 1)
		u := User{password: intern.RandomAlphanumeric(32)}
		Users[key] = u
		s, _ := store.New(req, "mqtt")
		s.Values["user-id"] = key
		err := s.Save(req, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

var store *sessions.CookieStore

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

	key := intern.RandomAlphanumeric(32)
	maxAge := 86400 * 30 // 30 days
	store = sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = false
	gothic.Store = store
	goth.UseProviders(
		wgtwo.New(
			*clientId,
			*clientSecret,
			*redirectUrl,
			"phone", "offline_access", "events.voice.subscribe", "events.voicemail.subscribe",
		),
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

	http.HandleFunc("/oauth/callback", callback)
	http.HandleFunc("/login", login)
	http.HandleFunc("/", index)

	httpServer := &http.Server{Addr: ":9099"}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			_ = httpServer.Close()
			done <- true
		}
	}()

	server := mqtt.New()
	tcp := listeners.NewTCP("t1", *tcpAddr)
	err := server.AddListener(tcp, &listeners.Config{
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

	opts := mqttc.NewClientOptions().AddBroker("tcp://localhost:1883").SetClientID("admin")
	opts.SetUsername("admin")
	opts.SetPassword(AdminPassword)
	mqttClient := mqttc.NewClient(opts)
	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	clientCredentialsConfig := &clientcredentials.Config{
		ClientID:     *clientId,
		ClientSecret: *clientSecret,
		Scopes: []string{
			"events.voice.subscribe",
			"events.voicemail.subscribe",
			"voicemail.get",
		},
		TokenURL: wgtwo.Endpoint.TokenURL,
	}

	token, err := clientCredentialsConfig.Token(context.Background())
	if err != nil {
		panic(err)
	}
	perRpc := oauth.NewOauthAccess(token)

	conn, err := grpc.Dial(
		"api.wgtwo.com:443",
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
		grpc.WithPerRPCCredentials(perRpc),
		grpc.WithStreamInterceptor(grpc_retry.StreamClientInterceptor()),
	)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	c := pb.NewEventsServiceClient(conn)

	eventTimeout, err := time.ParseDuration("10s")
	if err != nil {
		log.Panicln("Could not parse timeout")
	}

		marshaler := jsonpb.Marshaler{}

	go func() {
		log.Println("Starting subscription")
		ctx := context.Background()
		request := &pb.SubscribeEventsRequest{
			Type:          []pb.EventType{pb.EventType_VOICE_EVENT, pb.EventType_VOICEMAIL_EVENT},
			StartPosition: &pb.SubscribeEventsRequest_StartAtOldestPossible{},
			ClientId:      uuid.New().String(),
			QueueName:     intern.RandomAlphanumeric(12),
			DurableName:   intern.RandomAlphanumeric(12),
			//QueueName:     "wgtwo-mqtt",
			//DurableName:   "wgtwo-mqtt",
			MaxInFlight: 10,
			ManualAck: &pb.ManualAckConfig{
				Enable:  true,
				Timeout: ptypes.DurationProto(eventTimeout),
			},
		}
		r, err := c.Subscribe(
			ctx,
			request,
			grpc_retry.WithMax(MaxUint),
			grpc_retry.WithBackoff(grpc_retry.BackoffLinear(100*time.Millisecond)),
			grpc_retry.WithCodes(codes.ResourceExhausted, codes.Internal, codes.Unavailable, codes.Unknown, codes.DataLoss),)
		if err != nil {
			log.Panicln("Error while fetching events")
		}
		for {
			response, err := r.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				errStatus, _ := status.FromError(err)
				log.Fatalf("Could not get response: %s\n", errStatus.Code())
			}

			event := response.Event

			switch x := event.Event.(type) {
			case *pb.Event_VoiceEvent:
				log.Println("VOICE EVENT")
				json, err := marshaler.MarshalToString(response)
				if err != nil {
					log.Println(json)
				}

				owner := event.GetVoiceEvent().Owner.E164
				msisdn := strings.Replace(owner, "+", "", 1)
				topic := fmt.Sprintf("%s/events/voice/%s", msisdn, event.GetVoiceEvent().Type.String())
				mqttClient.Publish(topic, 2, false, json)

			case *pb.Event_VoicemailEvent:
				log.Println("VOICEMAIL EVENT")
				voicemailEvent := event.GetVoicemailEvent()
				if voicemailEvent.Type != pb.VoicemailEvent_NEW_VOICEMAIL {
					break
				}

				json, err := marshaler.MarshalToString(response)
				if err != nil {
					log.Println(json)
				}

				owner := event.GetVoicemailEvent().ToNumber.E164
				msisdn := strings.Replace(owner, "+", "", 1)
				topic := fmt.Sprintf("%s/events/voicemail", msisdn)
				mqttClient.Publish(topic, 2, false, json)
			default:
				log.Printf("Invalid event type: Event has unexpected type %T", x)
			}
			ackCtx, _ := context.WithTimeout(context.Background(), time.Second*10)
			c.Ack(ackCtx, &pb.AckRequest{Inbox: event.Metadata.AckInbox, Sequence: event.Metadata.Sequence})
		}
	}()

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
