package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an access token.
var googleOauthConfig = &oauth2.Config{
	//決定 API 伺服器在使用者完成授權流程後將使用者重新導向的位置
	//如果這個值與所提供的 client_id 的授權重新導向 URI 不符，API伺服器會回傳400 redirect_URL_mismatch
	// RedirectURL: "http://localhost:8000/auth/google/callback",
	RedirectURL: "http://localhost:8080/auth/callback",
	//憑證
	ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),

	//Google auth server 授權範圍
	Scopes: []string{"https://www.googleapis.com/auth/userinfo.email"},
	// Google auth server 的 endpoint
	Endpoint: google.Endpoint,
}

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func generateStateOauthCookie(c *gin.Context) string {

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	c.SetCookie("State", state, 10, "/", "localhost", false, true)
	return state
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.
	// 藉由Authorization Code去跟google(resource)申請Access Token
	ctx := context.Background()
	token, err := googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	// 拿到token後，與google交換使用者資訊
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

/*
	另一種寫法
	code := ctx.Query("code")
	token, err := google_config.Exchange(ctx, code)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

 藉由獲得的Access Token去跟google申請資源
	client := google_config.Client(context.TODO(), token)
	userInfo, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		_ = ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}
	defer userInfo.Body.Close()

	info, err := ioutil.ReadAll(userInfo.Body)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	var user googleUser
	err = json.Unmarshal(info, &user)
*/
