package database

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var DB *mongo.Client

func ConnectMongoDB() {
	// Ambil MongoDB URI dari environment variable
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		log.Fatalf("Environment variable MONGO_URI tidak ditemukan. Pastikan sudah diatur di secrets atau variable repository.")
	}

	// Membuat client MongoDB
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("Gagal membuat MongoDB client: %v", err)
	}

	// Mengatur timeout koneksi
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Menghubungkan ke MongoDB
	err = client.Connect(ctx)
	if err != nil {
		log.Fatalf("Gagal menghubungkan ke MongoDB: %v", err)
	}

	DB = client
	log.Println("Koneksi ke MongoDB berhasil!")
}

func GetCollection(collectionName string) *mongo.Collection {
	return DB.Database("myapi").Collection(collectionName)
}
