package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

type Claims struct {
	Account string
	Device  string
	jwt.StandardClaims
}

var jwtSecretSection = []byte("strongSecret")
var ctx = context.Background()

func loginJwtCheck(account string, serial string, device string) (token string) {
	fmt.Println("______________________logincheck started___________________________")
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	par := rdb.Exists(ctx, account)
	fmt.Println("status of token of key account:", par.Val())
	now := time.Now()
	// token exists in the redis
	// switch old token into denylist
	if par.Val() == 1 {
		fmt.Println("last token in redis")

		sexpireTime, err := rdb.Get(ctx, account).Result()
		if err != nil {
			log.Fatal(err)
		}

		expireTime, err := strconv.ParseInt(sexpireTime, 10, 64)
		if err != nil {
			log.Fatal(err)
		}

		sub := expireTime - (now.Unix())
		var duration time.Duration = time.Duration(sub) * time.Second
		fmt.Println("last token remain alive:", duration)
		//	..	expireTime = claims.ExpiresAt
		rdb.Del(ctx, account)
		fmt.Println("last token status:", rdb.Exists(ctx, account).Val())
		denylistid := account + strconv.FormatInt(now.Unix(), 10)
		rdb.Set(ctx, denylistid, expireTime, duration)

	}
	fmt.Println("generate new token for user")
	// generate new token for user
	secret := string(jwtSecretSection) + serial
	//secret := jwtSecretSection + []byte(serial)
	//	secret := jwtSecretSection.append([]byte(serial))
	allowlistid := account + strconv.FormatInt(now.Unix(), 10)
	claims := Claims{
		Account: account,
		Device:  device,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: now.Add(7 * 24 * time.Hour).Unix(),
			Id:        allowlistid,
			IssuedAt:  now.Unix(),
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	fmt.Println(tokenClaims)
	token, err := tokenClaims.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}
	rdb.Set(ctx, account, now.Add(7*24*time.Hour).Unix(), (7*24)*time.Hour)
	fmt.Println("_______________________logincheck finished___________________")
	return token
}

func signinInit(c *gin.Context) {
	c.HTML(http.StatusOK, "signin.html", nil)
}

func signinHandler(c *gin.Context) {
	account := c.PostForm("id")
	serial := c.PostForm("password")
	fmt.Println("User:", account)
	fmt.Println("Pwd:", serial)
	token := loginJwtCheck(account, serial, "PC")
	fmt.Println("token", token)
	func(c *gin.Context) {
		c.HTML(http.StatusOK, "signin.html", gin.H{
			"text": " Login success",
		})
	}(c)
}
func main() {
	r := gin.Default()
	r.LoadHTMLGlob("../*.html")
	r.GET("/signin", signinInit)
	r.POST("/signin", signinHandler)
	r.Run()

}
