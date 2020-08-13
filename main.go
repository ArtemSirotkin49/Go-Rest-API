package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"
	"transactions"
	"types"

	"constants"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// Handlers
func getTokensByIDHandler(w http.ResponseWriter, r *http.Request) {
	GUID := r.URL.Query().Get("GUID")
	if len(GUID) < constants.MinGUIDLength {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": constants.Error614}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	accessToken, err := generateJWT("access")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": err.Error()}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	refreshToken, err := generateJWT("refresh")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": err.Error()}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}

	if err := transactions.InsertTokensTransaction(accessToken, refreshToken, GUID); err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": err.Error()}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	response := map[string]string{"Status": constants.SuccessStatus, "accessToken": accessToken}
	responseJSON, _ := json.Marshal(response)
	http.SetCookie(w, changeCookie("refreshToken", refreshToken))
	http.SetCookie(w, changeCookie("GUID", GUID))
	w.Write(responseJSON)
}

func refreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	GUIDCookie, err := r.Cookie("GUID")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": constants.Error613}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	GUID := GUIDCookie.Value

	tokenCookie, err := r.Cookie("refreshToken")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": constants.Error615}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	refreshToken := tokenCookie.Value

	newAccessToken, err := generateJWT("access")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": err.Error()}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	newRefreshToken, err := generateJWT("refresh")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": err.Error()}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	newToken := types.Tokens{newAccessToken, newRefreshToken, GUID}

	err = transactions.RefreshTokensTransaction(newToken, refreshToken)
	if err == nil {
		response := map[string]string{"Status": constants.SuccessStatus, "accessToken": newAccessToken}
		responseJSON, _ := json.Marshal(response)
		http.SetCookie(w, changeCookie("refreshToken", newRefreshToken))
		http.SetCookie(w, changeCookie("GUID", GUID))
		w.Write(responseJSON)
		return
	}
	response := map[string]string{"Status": constants.ErrorStatus, "Error": err.Error()}
	responseJSON, _ := json.Marshal(response)
	w.Write(responseJSON)
}

func deleteTokenHandler(w http.ResponseWriter, r *http.Request) {
	GUIDCookie, err := r.Cookie("GUID")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": constants.Error613}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	GUID := GUIDCookie.Value

	tokenCookie, err := r.Cookie("refreshToken")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": constants.Error615}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	refreshToken := tokenCookie.Value

	err = transactions.DeleteTokenTransaction(GUID, refreshToken)
	if err == nil {
		response := map[string]string{"Status": constants.SuccessStatus}
		responseJSON, _ := json.Marshal(response)
		http.SetCookie(w, changeCookie("refreshToken", ""))
		http.SetCookie(w, changeCookie("GUID", ""))
		w.Write(responseJSON)
		return
	}
	response := map[string]string{"Status": constants.ErrorStatus, "Error": err.Error()}
	responseJSON, _ := json.Marshal(response)
	w.Write(responseJSON)
}

func deleteAllTokensHandler(w http.ResponseWriter, r *http.Request) {
	GUIDCookie, err := r.Cookie("GUID")
	if err != nil {
		response := map[string]string{"Status": constants.ErrorStatus, "Error": constants.Error613}
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
		return
	}
	GUID := GUIDCookie.Value

	err = transactions.DeleteAllTokensTransaction(GUID)
	if err == nil {
		response := map[string]string{"Status": constants.SuccessStatus}
		responseJSON, _ := json.Marshal(response)
		http.SetCookie(w, changeCookie("refreshToken", ""))
		http.SetCookie(w, changeCookie("GUID", ""))
		w.Write(responseJSON)
		return
	}
	response := map[string]string{"Status": constants.ErrorStatus, "Error": err.Error()}
	responseJSON, _ := json.Marshal(response)
	w.Write(responseJSON)
}

// Custom functions
func changeCookie(cookieName, cookieValue string) *http.Cookie {
	var maxAge int = constants.CookieMaxAge
	if len(cookieValue) == 0 {
		maxAge = -1
	}
	return &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		Domain:   constants.CookieDomain,
		Path:     constants.CookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   false,
	}
}

func generateJWT(tokenType string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	var signingKey = []byte(constants.AccessTokenKey)
	if tokenType == "refresh" {
		signingKey = []byte(constants.RefreshTokenKey)
	}
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", errors.New(constants.Error612)
	}
	return tokenString, nil
}

// Main
func main() {
	port := os.Getenv("PORT")
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/api/auth/").Subrouter()
	subrouter.HandleFunc("/get-tokens/", getTokensByIDHandler).Methods("GET")
	subrouter.HandleFunc("/refresh-tokens", refreshTokensHandler).Methods("POST")
	subrouter.HandleFunc("/delete-token", deleteTokenHandler).Methods("POST")
	subrouter.HandleFunc("/delete-all-tokens", deleteAllTokensHandler).Methods("POST")
	log.Fatal(http.ListenAndServe(port, router))
}
