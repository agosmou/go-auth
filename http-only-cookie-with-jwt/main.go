package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("my_secret_key")
var tokens []string

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func main() {
	r := gin.Default()
	r.POST("/login", gin.BasicAuth(gin.Accounts{
		"admin": "secret",
	}), func(c *gin.Context) {
		token, _ := generateJWT()
		tokens = append(tokens, token)

		// Set token as an HTTP-only cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "jwt",
			Value:    token,
			Expires:  time.Now().Add(5 * time.Minute),
			HttpOnly: true, // HTTP-only cookie
		})

		c.JSON(http.StatusOK, gin.H{
			"message": "logged in",
		})
	})

	r.GET("/resource", func(c *gin.Context) {
		// Retrieve the token from the cookie
		cookie, err := c.Request.Cookie("jwt")
		if err != nil {
			if err == http.ErrNoCookie {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "missing token",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "bad request",
			})
			return
		}
		tokenStr := cookie.Value

		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "unauthorized",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "bad request",
			})
			return
		}
		if !tkn.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": "resource data",
		})

	})
	r.Run("localhost:8080")
}

func generateJWT() (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: "username",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtKey)
}
