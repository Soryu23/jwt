package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

// custom claims
type Claims struct {
	Account string `json:"account_uuid"`
	Device  string `json:"device"`
	jwt.StandardClaims
}

// jwt secret key
// redis context
var jwtSecret = []byte("strongSecret")
var ctx = context.Background()

func main() {
	router := gin.Default()
	router.POST("/login", func(c *gin.Context) {
		// validate request body
		var body struct {
			Account  string
			Password string
		}
		err := c.ShouldBindJSON(&body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		// check account and password is correct
		if body.Account == "Kenny" && body.Password == "123456" {
			// now := time.Now()
			// jwtId := body.Account + strconv.FormatInt(now.Unix(), 10)
			// role := "Member"
			//			set claims and sign
			// claims := Claims{
			// Account: body.Account,
			// Role:    role,
			// StandardClaims: jwt.StandardClaims{
			// Audience:  body.Account,
			// ExpiresAt: now.Add(20 * time.Second).Unix(),
			// Id:        jwtId,
			// IssuedAt:  now.Unix(),
			// Issuer:    "ginJWT",
			// NotBefore: now.Add(10 * time.Second).Unix(),
			// Subject:   body.Account,
			// },
			// }
			// tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			// token, err := tokenClaims.SignedString(jwtSecret)
			// if err != nil {
			// c.JSON(http.StatusInternalServerError, gin.H{
			// "error": err.Error(),
			// })
			// return
			// }
			// c.JSON(http.StatusOK, gin.H{
			// "token": token,
			// })
			// return
			token := generateToken("Kennny")
			c.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		}
		// incorrect account or password
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Unauthorized",
		})
	})
	// protected member router
	authorized := router.Group("/")
	authorized.Use(AuthRequired)
	{
		authorized.GET("/member/profile", func(c *gin.Context) {
			if c.MustGet("account") == "Kenny" { //&& c.MustGet("role") == "Member" {
				c.JSON(http.StatusOK, gin.H{
					"name":  "Kenny",
					"age":   23,
					"hobby": "music",
				})
				return
			}
			c.JSON(http.StatusNotFound, gin.H{
				"error": "can not find the record",
			})
		})

	}
	router.Run()
}
func startClient() {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	return rdb

}

func generateToken(account string, device string, serial string) (token string) {
	sc := jwtSecret
	now := time.Now()

	jwtId := account + strconv.FormatInt(now.Unix(), 10)

	claims := Claims{
		Account: account,
		Device:  device,
		StandardClaims: jwt.StandardClaims{
			//Audience:  account,
			ExpiresAt: now.Add(7 * 24 * time.Hour).Unix(),
			Id:        jwtId,
			IssuedAt:  now.Unix(),
			//Issuer:    "ginJWT",
			//NotBefore: now.Add(300 * time.Second).Unix(),
			//Subject:   account,
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString(serial + sc)
	fmt.Println(token)
	if err != nil {
		log.Fatal(err)
		return
	}

	rdb := startClient()
	defer rdb.Close()
	err = rdb.Set(ctx, account, claims, 0).Err()

	if err != nil {
		panic(err)
	}

	return token

}

func parseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	var message error
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				message = "token is malformed"
			} else if ve.Errors&jwt.ValidationErrorUnverifiable != 0 {
				message = "token could not be verified because of signing problems"
			} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				message = "signature validation failed"
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				message = "token is expired"
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				message = "token is not yet valid before sometime"
			} else {
				message = "can not handle this token"
			}
		}
		return nil, message
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		account := claims.Account
		rdb := startClient()
		defer rdb.Close()
		val, err := rdb.Get(ctx, "key").Result()
		if err != nil {
			return nil, err
		}
		return claims, nil
	}
	message = "tokenInvalid"
	return nil, message
}

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		token := strings.Split(auth, "Bearer ")[1]
		if token == "" {
			middleware.ResponseError(c, -1, errors.New("请求未携带token，无权限访问"))
			func(c *gin.Context) {
				c.HTML(HttpStatus, "/a", gin.H{
					"error": "未携带token",
				})
			}(c)
			c.Abort()
			return
		}
		log.Print("get token: ", token)
		//j := NewJWT()
		// parseToken 解析token包含的信息
		claims, err := jwt.ParseToken(token)
		fmt.Println("claims", claims)
		if err != nil {
			if err == TokenExpired {
				middleware.ResponseError(c, -1, errors.New("授权已过期"))
				c.Abort()
				return
			}
			middleware.ResponseError(c, -1, err)
			c.Abort()
			return
		}
		// 继续交由下一个路由处理,并将解析出的信息传递下去
		c.Set("claims", claims)
	}
}

// validate JWT
func AuthRequired(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	token := strings.Split(auth, "Bearer ")[1]
	// parse and validate token for six things:
	// validationErrorMalformed => token is malformed
	// validationErrorUnverifiable => token could not be verified because of signing problems
	// validationErrorSignatureInvalid => signature validation failed
	// validationErrorExpired => exp validation failed
	// validationErrorNotValidYet => nbf validation failed
	// validationErrorIssuedAt => iat validation failed
	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (i interface{}, err error) {
		return jwtSecret, nil
	})
	if err != nil {
		var message string
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				message = "token is malformed"
			} else if ve.Errors&jwt.ValidationErrorUnverifiable != 0 {
				message = "token could not be verified because of signing problems"
			} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				message = "signature validation failed"
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				message = "token is expired"
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				message = "token is not yet valid before sometime"
			} else {
				message = "can not handle this token"
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": message,
		})
		c.Abort()
		return
	}
	if claims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
		fmt.Println("account:", claims.Account)
		//fmt.Println("role:", claims.Role)
		c.Set("account", claims.Account)
		//c.Set("role", claims.Role)
		c.Next()
	} else {
		c.Abort()
		return
	}
}
