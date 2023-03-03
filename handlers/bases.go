package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

// 1.
func RegisterAPIHandlers(router *gin.Engine) {

	r := router.Group("/auth")
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	// 切成兩個 ，一個要經過認證，一個不需要，用來給google認證完後進行Callback
	r.GET("/callback", callback)

	authGroup := r.Group("/google").Use(AuthMiddleware())
	{
		// 2. 打到/auth/google/hello 需要經過AuthMiddleware，檢查是否有經過google
		authGroup.GET("/hello", Hello)

	}
}

var state string

// 3. 檢查是否有經過google，沒有的話進入Oauth，轉跳到google網頁上
// 待查  >> 該怎麼放已經登入過的資訊
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookieToken, err := c.Cookie("TOKEN_KEY")
		if err != nil && cookieToken != "TOKEN_KEY_VERIFY" {
			state = generateStateOauthCookie(c) // 需要產生 state 防止CSRF

			session := sessions.Default(c)
			session.Set("state", state)
			session.Set("Request_URL_Path", c.Request.URL.Path)
			err := session.Save()
			if err != nil {
				_ = c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			/*
				上面做測試用，用來實現驗證State，待查>該怎麼實現驗證state
			*/
			/*
				state 為了防止CSRF(跨站請求偽造)攻擊而設置的。建議可以透過隨機產生的方式來產生出一個 state
				當 Google server 驗證完後，會原封不動地把 state 再回傳給網站 server，
				如此一來我們就可以驗證 state 是否為網站所發出的 state，以確保正確性
			*/
			// 轉跳到google認證網頁 後段渲染回前端
			c.Redirect(http.StatusTemporaryRedirect, googleOauthConfig.AuthCodeURL(state))
			c.AbortWithStatus(http.StatusTemporaryRedirect)
			return
		} else {
			c.Set("User", "TEST_ACCOUNT")
			c.Next()
		}
	}
}

func callback(c *gin.Context) {
	/*
		google server 認證完成後需要有一個 Client端的api轉跳回來
	*/
	session := sessions.Default(c)
	state := session.Get("state")
	p := c.Query("state")
	if state != p {
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("state error."))
		return
	}
	code := c.Query("code")
	/*
		拿著資料token跟google server取得用戶資料
	*/
	data, err := getUserDataFromGoogle(code)
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	fmt.Println(string(data))
	// 設置cookie 讓跳回Middleware有辦法認證已經授權
	c.SetCookie("TOKEN_KEY", "TOKEN_KEY_VERIFY", 10, "/", "localhost", false, true)
	// 方便跳回使用者原本要進入的api，會一樣再走一次Middleware
	TargetURL := session.Get("Request_URL_Path").(string)
	/*
		跳回指定頁面
	*/
	c.Redirect(http.StatusSeeOther, TargetURL)
}

func Hello(c *gin.Context) {
	/*
		成功的話，畫面應該會跳出LoginSUCCESS
	*/
	fmt.Println("LoginSUCCESS")
	c.String(200, "LoginSUCCESS")

}
