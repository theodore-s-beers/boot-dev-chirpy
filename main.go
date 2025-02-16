package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/theodore-s-beers/foo/internal/auth"
	"github.com/theodore-s-beers/foo/internal/database"
)

type apiConfig struct {
	db             *database.Queries
	fileserverHits atomic.Int32
	platform       string
	jwtSecret      string
}

type errorRes struct {
	Error string `json:"error"`
}

type chirpRes struct {
	ID        uuid.UUID `json:"id"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)

	platform := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")

	apiCfg := apiConfig{
		db:        dbQueries,
		platform:  platform,
		jwtSecret: jwtSecret,
	}

	serveMux := http.NewServeMux()
	serverStruct := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	serveMux.Handle("GET /admin/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", apiCfg.fileserverHits.Load())))
	}))

	serveMux.Handle("POST /admin/reset", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiCfg.platform != "dev" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		err := apiCfg.db.DeleteAllUsers(r.Context()) // Should also delete their chirps
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		apiCfg.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
	}))

	serveMux.Handle("POST /api/users", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type userReq struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		type userRes struct {
			ID        uuid.UUID `json:"id"`
			Email     string    `json:"email"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
		}

		w.Header().Set("Content-Type", "application/json") // Response is JSON regardless

		var req userReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorRes{Error: "Invalid JSON payload"})
			return
		}

		hashedPwd, err := auth.HashPassword(req.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errorRes{Error: "Failed to hash password"})
			return
		}

		dbUser, err := apiCfg.db.CreateUser(r.Context(), database.CreateUserParams{
			Email:          req.Email,
			HashedPassword: hashedPwd,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errorRes{Error: "Failed to add user to database"})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(userRes{
			ID:        dbUser.ID,
			Email:     dbUser.Email,
			CreatedAt: dbUser.CreatedAt,
			UpdatedAt: dbUser.UpdatedAt,
		})
	}))

	serveMux.Handle("POST /api/chirps", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type chirpReq struct {
			Body string `json:"body"`
		}

		w.Header().Set("Content-Type", "application/json") // Response is JSON regardless

		var req chirpReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorRes{Error: "Invalid JSON payload"})
			return
		}

		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errorRes{Error: err.Error()})
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.jwtSecret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errorRes{Error: err.Error()})
			return
		}

		if len(req.Body) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorRes{Error: "Chirp text is empty"})
			return
		}

		if len(req.Body) > 140 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorRes{Error: "Chirp is too long"})
			return
		}

		// words := strings.Fields(req.Body)
		// for i := 0; i < len(words); i++ {
		// 	lowercase := strings.ToLower(words[i])
		// 	if lowercase == "fornax" || lowercase == "kerfuffle" || lowercase == "sharbert" {
		// 		words[i] = "****"
		// 	}
		// }
		// cleaned := strings.Join(words, " ")

		dbChirp, err := apiCfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   req.Body,
			UserID: userID,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errorRes{Error: "Failed to add chirp to database"})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(chirpRes{
			ID:        dbChirp.ID,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
		})
	}))

	serveMux.Handle("GET /api/chirps", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json") // Response is JSON regardless

		chirps, err := apiCfg.db.GetAllChirps(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errorRes{Error: "Failed to fetch chirps from database"})
			return
		}

		resChirps := make([]chirpRes, len(chirps))
		for i, chirp := range chirps {
			resChirps[i] = chirpRes{
				ID:        chirp.ID,
				Body:      chirp.Body,
				UserID:    chirp.UserID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resChirps)
	}))

	serveMux.Handle("GET /api/chirps/{chirpID}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json") // Response is JSON regardless

		chirpIDStr := r.PathValue("chirpID")
		chirpID, err := uuid.Parse(chirpIDStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorRes{Error: "Invalid chirp ID"})
			return
		}

		dbChirp, err := apiCfg.db.GetChirpByID(r.Context(), chirpID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(errorRes{Error: "Chirp not found in database"})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(chirpRes{
			ID:        dbChirp.ID,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
		})
	}))

	serveMux.Handle("POST /api/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type loginReq struct {
			Email            string `json:"email"`
			Password         string `json:"password"`
			ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
		}

		type loginRes struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Email     string    `json:"email"`
			Token     string    `json:"token"`
		}

		w.Header().Set("Content-Type", "application/json") // Response is JSON regardless

		var req loginReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorRes{Error: "Invalid JSON payload"})
			return
		}

		dbUser, err := apiCfg.db.GetUserByEmail(r.Context(), req.Email)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errorRes{Error: "Invalid email or password"})
			return
		}

		if err := auth.CheckPasswordHash(req.Password, dbUser.HashedPassword); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(errorRes{Error: "Invalid email or password"})
			return
		}

		var expiration time.Duration
		if req.ExpiresInSeconds == 0 {
			expiration = time.Hour
		} else {
			expiration = time.Duration(req.ExpiresInSeconds) * time.Second
		}
		token, err := auth.MakeJWT(dbUser.ID, apiCfg.jwtSecret, expiration)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(errorRes{Error: "Failed to generate JWT"})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(loginRes{
			ID:        dbUser.ID,
			CreatedAt: dbUser.CreatedAt,
			UpdatedAt: dbUser.UpdatedAt,
			Email:     dbUser.Email,
			Token:     token,
		})
	}))

	serverStruct.ListenAndServe()
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
