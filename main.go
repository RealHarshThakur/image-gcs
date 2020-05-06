package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"cloud.google.com/go/storage"
	"github.com/gabriel-vasile/mimetype"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyz"

// Username defines name of the user
type Username struct {
	Username string `json:"username" validate:"required"`
}

type Message struct {
	Message string `json:"message"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func createBucket(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	creds, err := google.FindDefaultCredentials(ctx, storage.ScopeReadOnly)
	if err != nil {
		log.Fatal(err)
	}

	client, err := storage.NewClient(ctx, option.WithCredentials(creds))

	if err != nil {

		http.Error(w, " Issue with connecting to storage", http.StatusInternalServerError)
		log.Fatal(err)
		return

	}

	var u Username
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&u)
	if err != nil {

		http.Error(w, " Invalid data", http.StatusPreconditionFailed)
		return
	}

	randstring := randStringBytes(7)
	bucketname := u.Username + "_" + randstring
	log.Println(bucketname)
	bucketexist := checkbucketexist(bucketname)
	if bucketexist {
		http.Error(w, "Bucket for this user already exists", http.StatusBadRequest)
		return
	}
	bkt := client.Bucket(bucketname)
	if err := bkt.Create(ctx, "steady-service-269616", nil); err != nil {
		http.Error(w, "Sorry, bucket creation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	var m Message
	m.Message = "Created the bucket: " + bucketname
	json.NewEncoder(w).Encode(m)

}

func countobject(bucketname string) int {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatal("Problem connecting to storage")
	}

	bucketexist := checkbucketexist(bucketname)
	if bucketexist {
		bkt := client.Bucket(bucketname)

		var names []string
		count := 0
		it := bkt.Objects(ctx, nil)
		for {
			attrs, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			names = append(names, attrs.Name)
			count++
		}
		return count
	}

	return 0
}

func checkbucketexist(bucketname string) bool {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	bucket := client.Bucket(bucketname)
	_, err = bucket.Attrs(ctx)
	if err != nil {
		log.Println("Message: ", err)
		return false
	}
	log.Println("Bucket exists: ", bucketname)
	return true
}

func addobject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucketname := vars["bucketname"]
	bucketexist := checkbucketexist(bucketname)
	if bucketexist {
		count := countobject(bucketname)
		if count < 4 {
			if err := r.ParseMultipartForm(32 << 20); err != nil {
				log.Println("Could not parse multipart form: ", err)
				http.Error(w, "CANT_PARSE_FORM", http.StatusInternalServerError)
			}

			file, fileHeader, err := r.FormFile("file")

			fileSize := fileHeader.Size
			if fileSize > 32<<20 {

				http.Error(w, "FILE_TOO_BIG", http.StatusBadRequest)

			}
			fileBytes, err := ioutil.ReadAll(file)
			if err != nil {
				log.Println(err)
				http.Error(w, "INVALID_FILE", http.StatusBadRequest)

			}
			mime := mimetype.Detect(fileBytes)
			newFile := bytes.NewReader(fileBytes)

			filetype := http.DetectContentType(fileBytes)
			if filetype != "image/jpeg" && filetype != "image/jpg" &&
				filetype != "image/gif" && filetype != "image/png" {
				http.Error(w, "INVALID_FILE_TYPE", http.StatusBadRequest)
				log.Fatal(filetype)
				return

			}
			fileName := bucketname
			fileExt := mime.Extension()
			count++
			strCount := strconv.Itoa(count)
			newfilename := fileName + strCount + fileExt
			ctx := context.Background()
			client, err := storage.NewClient(ctx)

			ctx, cancel := context.WithTimeout(ctx, time.Second*50000)
			defer cancel()

			wc := client.Bucket(bucketname).Object(newfilename).NewWriter(ctx)
			wc.ContentType = filetype
			if _, err = io.Copy(wc, newFile); err != nil {
				log.Println(err)
				http.Error(w, "Unable to upload file", http.StatusInternalServerError)
			}
			if err := wc.Close(); err != nil {
				log.Println(err)
				http.Error(w, "Image wasn't uploaded ", http.StatusInternalServerError)
				return
			}
			log.Println("The image name is: ", newfilename)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			var m Message
			m.Message = "Uploaded the picture: " + newfilename
			json.NewEncoder(w).Encode(m)
		} else {
			http.Error(w, "You have enough pictures", http.StatusPreconditionRequired)
		}
	} else {
		http.Error(w, "Bucket doesn't exist", http.StatusPreconditionRequired)
	}

}

func deleteObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucketname := vars["bucketname"]
	objectname := vars["objectname"]
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		http.Error(w, "Error connecting to the storage", http.StatusInternalServerError)
	}

	bucket := client.Bucket(bucketname)

	if err := bucket.Object(objectname).Delete(ctx); err != nil {
		http.Error(w, "Error in deleting the object", http.StatusInternalServerError)
		return
	}

	log.Println("Successfully deleted this object : ", objectname)
	w.Header().Set("Content-Type", "application/json")
	var m Message
	m.Message = "Deleted the picture: " + objectname
	json.NewEncoder(w).Encode(m)
}

func main() {

	sm := mux.NewRouter()
	l := log.New(os.Stdout, "buckets ", log.LstdFlags)
	postRouter := sm.Methods(http.MethodPost).Subrouter()
	postRouter.HandleFunc("/bucket", createBucket)

	uploadRouter := sm.Methods(http.MethodPost).Subrouter()
	uploadRouter.HandleFunc("/bucket/{bucketname}", addobject)

	deleteRouter := sm.Methods(http.MethodDelete).Subrouter()
	deleteRouter.HandleFunc("/bucket/{bucketname}/{objectname}", deleteObject)

	s := http.Server{
		Addr:         "127.0.0.1:5000", // configure the bind address
		Handler:      sm,               // set the default handler
		ErrorLog:     l,
		ReadTimeout:  5 * time.Second,   // max time to read request from the client
		WriteTimeout: 10 * time.Second,  // max time to write response to the client
		IdleTimeout:  120 * time.Second, // max time for connections using TCP Keep-Alive
	}

	// start the server
	go func() {
		l.Println("Starting the server")

		err := s.ListenAndServe()
		if err != nil {
			os.Exit(1)
		}
	}()

	// trap sigterm or interupt and gracefully shutdown the server
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, os.Kill)

	// Block until a signal is received.
	sig := <-c
	log.Println("Got signal:", sig)

	// gracefully shutdown the server, waiting max 30 seconds for current operations to complete
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	s.Shutdown(ctx)
}
