package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
)

// ProxyFile связывает страну с файлом
type ProxyFile struct {
	File    string
	Country string
}

var (
	proxyFiles []ProxyFile
	filesMutex sync.RWMutex // безопасность при обновлениях
)

var mu sync.Mutex

func main() {
	loadProxyFiles() // первый раз загружаем файлы
	app := fiber.New()

	// Обслуживание статики (заменяет app.Static)
	app.Use("/static/", func(c fiber.Ctx) error {
		return c.SendFile("./static" + c.Path()[len("/static"):])
	})

	app.Get("/", func(c fiber.Ctx) error {
		html := `
	<!DOCTYPE html>
	<html>
	<head><title>Login</title></head>
	<body>
		<h2>Proxy Admin Panel</h2>
		<form method="POST" action="/login">
			<input type="text" name="username" placeholder="Username" required>
			<input type="password" name="password" placeholder="Password" required>
			<button type="submit">Login</button>
		</form>
	</body>
	</html>`
		return c.Type("html").SendString(html)
	})

	app.Post("/login", func(c fiber.Ctx) error {
		username := c.FormValue("username")
		password := c.FormValue("password")

		// Пример простой проверки
		if username == "admin" && password == "123456" {
			c.Cookie(&fiber.Cookie{
				Name:     "auth",
				Value:    "true",
				Expires:  time.Now().Add(24 * time.Hour),
				HTTPOnly: true,
				SameSite: "Lax",
			})
			return c.Redirect().To("/dashboard")
		}

		return c.SendString("Invalid credentials")
	})

	// Пример POST-маршрута
	app.Post("/add-proxy", func(c fiber.Ctx) error {
		country := c.FormValue("country")
		proxy := c.FormValue("proxy")
		format := c.FormValue("format")

		log.Printf("Добавлен прокси: %s -> %s (формат %s)", country, proxy, format)

		// Здесь будет логика добавления прокси в файл
		return c.Redirect().To("/dashboard")
	})

	// Добавление новой страны с созданием соотвествующейго файла "Country Code"_proxies в папке proxies
	app.Post("/add-country", func(c fiber.Ctx) error {
		countryName := c.FormValue("countryName")
		countryCode := strings.ToLower(c.FormValue("countryCode"))

		if countryName == "" || countryCode == "" {
			return c.SendString("Both fields are required.")
		}

		filename := fmt.Sprintf("proxies/%s_proxies.txt", countryName)

		file, err := os.Create(filename)
		if err != nil {
			log.Printf("Error creating file %s: %v", filename, err)
			return c.SendString(fmt.Sprintf("Could not create file: %v", err))
		}
		defer file.Close()

		// Обновляем список файлов
		loadProxyFiles()

		// Сохраняем сообщение в куке
		c.Cookie(&fiber.Cookie{
			Name:     "flash",
			Value:    "✅ Страна " + countryName + " (" + countryCode + ") добавлена",
			Expires:  time.Now().Add(5 * time.Second),
			HTTPOnly: true,
			SameSite: "Lax",
		})

		return c.Redirect().To("/dashboard")
	})

	// Пример маршрутов с параметрами
	app.Get("/delete/:country/:proxy", func(c fiber.Ctx) error {
		country := c.Params("country")
		proxy := c.Params("proxy")
		log.Printf("Удалён прокси: %s -> %s", country, proxy)

		return c.Redirect().To("/dashboard")
	})

	app.Get("/quarantine/:country/:proxy", func(c fiber.Ctx) error {
		country := c.Params("country")
		proxy := c.Params("proxy")
		log.Printf("Прокси переведён в карантин: %s -> %s", country, proxy)

		return c.Redirect().To("/dashboard")
	})

	app.Get("/dequarantine/:country/:proxy", func(c fiber.Ctx) error {
		country := c.Params("country")
		proxy := c.Params("proxy")
		log.Printf("Прокси восстановлен из карантина: %s -> %s", country, proxy)

		return c.Redirect().To("/dashboard")
	})

	// Дашборд
	app.Get("/dashboard", dashboard)

	// Запуск авто-карантина (заглушка)
	go autoQuarantineCheck()

	log.Println("Server started on http://localhost:3000")
	app.Listen(":3000")
}

func loadProxyFiles() {
	filesMutex.Lock()
	defer filesMutex.Unlock()

	proxyFiles = nil // очищаем перед перезагрузкой

	files, err := os.ReadDir("proxies")
	if err != nil {
		log.Printf("Не могу прочитать папку proxies: %v", err)
		return
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), "_proxies.txt") {
			countryCode := strings.TrimSuffix(file.Name(), "_proxies.txt")
			countryName := strings.ToUpper(countryCode[:1]) + strings.ToLower(countryCode[1:])
			proxyFiles = append(proxyFiles, ProxyFile{
				File:    "proxies/" + file.Name(),
				Country: countryName,
			})
		}
	}
}

func autoQuarantineCheck() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for _, pf := range proxyFiles {
			proxies, _ := getProxiesFromFile(pf.File)
			for _, proxy := range proxies {
				if isUnreachable(proxy) {
					setAutoQuarantine(pf.File, proxy)
				} else {
					outAutoQuarantine(pf.File, proxy)
				}
			}
		}
	}
}

func isUnreachable(proxy string) bool {
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return true
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			MaxIdleConns:    10,
			IdleConnTimeout: 5 * time.Second,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://ipinfo.io/json")
	if err != nil || resp.StatusCode != 200 {
		return true
	}
	return false
}

func getProxiesFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var result []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "peer "):
			result = append(result, strings.TrimPrefix(line, "peer "))

		case strings.HasPrefix(line, "quarantine "):
			result = append(result, "quarantine "+strings.TrimPrefix(line, "quarantine "))

		case strings.HasPrefix(line, "autoquarantine "):
			result = append(result, "autoquarantine "+strings.TrimPrefix(line, "autoquarantine "))
		}
	}

	return result, nil
}

// func getProxiesFromFile(filePath string) ([]string, error) {
// 	data, err := os.ReadFile(filePath)
// 	if err != nil {
// 		return nil, err
// 	}

// 	lines := strings.Split(string(data), "\n")
// 	var result []string
// 	for _, line := range lines {
// 		line = strings.TrimSpace(line)
// 		if strings.HasPrefix(line, "peer ") {
// 			result = append(result, strings.TrimPrefix(line, "peer "))
// 		}
// 		if strings.HasPrefix(line, "autoquarantine ") {
// 			result = append(result, "QUARANTINE "+strings.TrimPrefix(line, "autoquarantine "))
// 		}
// 	}
// 	return result, nil
// }

func setAutoQuarantine(filename, proxy string) error {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "peer "+proxy) {
			line = "autoquarantine " + proxy
		}
		lines = append(lines, line)
	}

	return os.WriteFile(filename, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func outAutoQuarantine(filename, proxy string) error {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "autoquarantine "+proxy) {
			line = "peer " + proxy
		}
		lines = append(lines, line)
	}

	return os.WriteFile(filename, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// handlers/proxy_handlers.go
func dashboard(c fiber.Ctx) error {
	auth := c.Cookies("auth") != ""
	if !auth {
		return c.Redirect().To("/")
	}

	// Получаем сообщение из куки
	flashMsg := c.Cookies("flash", "")
	if flashMsg != "" {
		// Удаляем куку после чтения
		c.Cookie(&fiber.Cookie{
			Name:     "flash",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			SameSite: "Lax",
		})
	}

	proxyMap := make(map[string][]string)
	for _, pf := range proxyFiles {
		proxies, _ := getProxiesFromFile(pf.File)
		proxyMap[pf.Country] = proxies
	}

	var html strings.Builder

	html.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Proxy Admin Panel</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>`)

	// Выводим сообщение, если оно есть
	if flashMsg != "" {
		html.WriteString(fmt.Sprintf(`
<div id="flashMessage" style="
    position: fixed;
    top: 20px;
    right: 20px;
    background-color: #d4edda;
    color: #155724;
    padding: 10px 20px;
    border-radius: 5px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    z-index: 9999;
    transition: opacity 0.5s;
">%s</div>
<script>
    setTimeout(function() {
        var msg = document.getElementById('flashMessage');
        if (msg) {
            msg.style.opacity = '0';
            setTimeout(function() { msg.remove(); }, 500);
        }
    }, 3000);
</script>`, flashMsg))
	}

	html.WriteString(`
<h1>Proxy List by Country</h1>

<form method="POST" action="/add-proxy">
<select name="country">`)
	filesMutex.RLock()
	for _, pf := range proxyFiles {
		html.WriteString(fmt.Sprintf(`<option value="%s">%s</option>`, pf.Country, pf.Country))
	}
	filesMutex.RUnlock()
	html.WriteString(`</select>
<input type="text" name="proxy" placeholder="addr:port:user:pass or socks5://..." required>
<select name="format">
<option value="1">Format 1: addr:port:user:pass</option>
<option value="2">Format 2: proto://addr:port:user:pass</option>
<option value="3">Format 3: user:pass@addr:port</option>
<option value="4">Format 4: proto://user:pass@addr:port</option>
</select>
<button type="submit">Add Proxy</button>
</form>

<h2>Add Country</h2>
<form method="POST" action="/add-country">
<input type="text" name="countryName" placeholder="Country Name (e.g., Germany)" required>
<input type="text" name="countryCode" placeholder="Country Code (e.g., DE)" required>
<button type="submit">Add Country</button>
</form>
`)

	for country, proxies := range proxyMap {
		html.WriteString(fmt.Sprintf("<h2>%s</h2><ul>", country))
		for _, proxy := range proxies {
			html.WriteString("<li>")

			if strings.HasPrefix(proxy, "quarantine ") {
				cleanProxy := proxy[11:] // убираем "quarantine "
				html.WriteString(fmt.Sprintf("🟡 Quarantined: %s <a href=\"/dequarantine/%s/%s\">Restore</a>",
					cleanProxy, url.QueryEscape(country), url.QueryEscape(cleanProxy)))
			} else if strings.HasPrefix(proxy, "autoquarantine ") {
				cleanProxy := proxy[14:] // убираем "autoquarantine "
				html.WriteString(fmt.Sprintf("🔴 Autoquarantined: %s <a href=\"/dequarantine/%s/%s\">Restore</a>",
					cleanProxy, url.QueryEscape(country), url.QueryEscape(cleanProxy)))
			} else {
				html.WriteString(fmt.Sprintf("🟢 Active: %s <a href=\"/quarantine/%s/%s\"> Quarantine</a> <a href=\"/delete/%s/%s\">Delete</a>",
					proxy, url.QueryEscape(country), url.QueryEscape(proxy), url.QueryEscape(country), url.QueryEscape(proxy)))
			}

			html.WriteString("</li>")
		}
		html.WriteString("</ul>")
	}

	html.WriteString(`</body></html>`)

	return c.Type("html", "utf-8").SendString(html.String())
}

// func dashboard(c fiber.Ctx) error {
// 	auth := c.Cookies("auth") != ""
// 	if !auth {
// 		return c.Redirect().To("/")
// 	}

// 	proxyMap := make(map[string][]string)
// 	for _, pf := range proxyFiles {
// 		proxies, _ := getProxiesFromFile(pf.File)
// 		proxyMap[pf.Country] = proxies
// 	}

// 	// Генерация HTML вручную
// 	var html strings.Builder

// 	// Получаем сообщение из query-параметра
// 	message := c.Query("message")

// 	html.WriteString(`<!DOCTYPE html>
// 	<html>
// 	<head>
// 	<meta charset="UTF-8">
// 	<title>Proxy Admin Panel</title>
// 	<link rel="stylesheet" href="/static/style.css">
// 	</head>
// 	<body>`)

// 	// Выводим сообщение, если оно есть
// 	if message != "" {
// 		// Экранируем для безопасности
// 		safeMessage := url.QueryEscape(message)
// 		html.WriteString(fmt.Sprintf(`
// 	<div id="flashMessage" style="
// 		position: fixed;
// 		top: 20px;
// 		right: 20px;
// 		background-color: #d4edda;
// 		color: #155724;
// 		padding: 10px 20px;
// 		border-radius: 5px;
// 		box-shadow: 0 2px 10px rgba(0,0,0,0.1);
// 		z-index: 9999;
// 		transition: opacity 0.5s;
// 	">%s</div>
// 	<script>
// 		setTimeout(function() {
// 			var msg = document.getElementById('flashMessage');
// 			if (msg) {
// 				msg.style.opacity = '0';
// 				setTimeout(function() { msg.remove(); }, 500);
// 			}
// 		}, 3000);
// 	</script>`, safeMessage))
// 	}

// 	// Основной контент
// 	html.WriteString(`
// 	<h1>Proxy List by Country</h1>

// 	<form method="POST" action="/add-proxy">
// 	<select name="country">
// 	<option value="Russia">Russia</option>
// 	<option value="USA">USA</option>
// 	</select>
// 	<input type="text" name="proxy" placeholder="addr:port:user:pass or socks5://..." required>
// 	<select name="format">
// 	<option value="1">Format 1: addr:port:user:pass</option>
// 	<option value="2">Format 2: proto://addr:port:user:pass</option>
// 	<option value="3">Format 3: user:pass@addr:port</option>
// 	<option value="4">Format 4: proto://user:pass@addr:port</option>
// 	</select>
// 	<button type="submit">Add Proxy</button>
// 	</form>`)

// 	for country, proxies := range proxyMap {
// 		html.WriteString(fmt.Sprintf("<h2>%s</h2><ul>", country))
// 		for _, proxy := range proxies {
// 			html.WriteString("<li>")

// 			if len(proxy) > 8 && proxy[:9] == "quarantine " {
// 				cleanProxy := proxy[9:]
// 				html.WriteString(fmt.Sprintf("🟡 Quarantined: %s <a href=\"/dequarantine/%s/%s\">Restore</a>",
// 					cleanProxy, url.QueryEscape(country), url.QueryEscape(cleanProxy)))
// 			} else if strings.HasPrefix(proxy, "autoquarantine ") {
// 				cleanProxy := strings.TrimPrefix(proxy, "autoquarantine ")
// 				html.WriteString(fmt.Sprintf("🔴 Autoquarantined: %s <a href=\"/dequarantine/%s/%s\">Restore</a>",
// 					cleanProxy, url.QueryEscape(country), url.QueryEscape(cleanProxy)))
// 			} else {
// 				html.WriteString(fmt.Sprintf("🟢 Active: %s <a href=\"/quarantine/%s/%s\"> Quarantine</a> <a href=\"/delete/%s/%s\">Delete</a>",
// 					proxy, url.QueryEscape(country), url.QueryEscape(proxy), url.QueryEscape(country), url.QueryEscape(proxy)))
// 			}

// 			html.WriteString("</li>")
// 		}
// 		html.WriteString("</ul>")
// 	}

// 	html.WriteString(`</body></html>`)

// 	return c.Type("html", "utf-8").SendString(html.String())
// }

func deleteProxy(c fiber.Ctx) error {
	country := c.Params("country")
	proxy := c.Params("proxy")
	for _, pf := range proxyFiles {
		if pf.Country == country {
			removeProxyFromFile(pf.File, proxy)
		}
	}
	return c.Redirect().To("/dashboard")
}

func quarantineProxy(c fiber.Ctx) error {
	country := c.Params("country")
	proxy := c.Params("proxy")
	for _, pf := range proxyFiles {
		if pf.Country == country {
			setquarantineProxyFromFile(pf.File, proxy)
		}
	}
	return c.Redirect().To("/dashboard")
}

func dequarantineProxy(c fiber.Ctx) error {
	country := c.Params("country")
	proxy := c.Params("proxy")
	for _, pf := range proxyFiles {
		if pf.Country == country {
			outquarantineProxyFromFile(pf.File, proxy)
		}
	}
	return c.Redirect().To("/dashboard")
}

func addProxy(c fiber.Ctx) error {
	country := c.FormValue("country")
	proxy := c.FormValue("proxy")
	format := c.FormValue("format")

	switch format {
	case "1":
		parts := strings.Split(proxy, ":")
		if len(parts) >= 4 {
			proxy = fmt.Sprintf("socks5h://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
		}
	case "2":
		sep := strings.SplitN(proxy, "://", 2)
		if len(sep) == 2 {
			parts := strings.Split(sep[1], ":")
			if len(parts) >= 4 {
				proxy = fmt.Sprintf("%s://%s:%s@%s:%s", sep[0], parts[2], parts[3], parts[0], parts[1])
			}
		}
	case "3":
		proxy = "socks5h://" + proxy
	case "4":
		// уже в формате proto://user:pass@host:port
		break
	default:
		return c.SendString("Invalid format")
	}

	for _, pf := range proxyFiles {
		if pf.Country == country {
			addProxyToFile(pf.File, proxy)
		}
	}
	return c.Redirect().To("/")
}

func logs(c fiber.Ctx) error {
	logData, err := os.ReadFile("logs/unsuccessful")
	if err != nil {
		return c.SendString("Failed to read log file")
	}
	return c.SendString("<pre>" + string(logData) + "</pre>")
}

func removeProxyFromFile(filename string, proxy string) error {
	// Открываем файл для чтения
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Читаем содержимое файла построчно
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Проверяем, начинается ли строка с "peer " и содержит ли нужный прокси
		if strings.HasPrefix(line, "peer ") {
			existingProxy := strings.TrimSpace(strings.TrimPrefix(line, "peer "))
			if existingProxy == proxy {
				// Пропускаем эту строку (не добавляем в список), тем самым удаляя её
				continue
			}
		}

		// Все остальные строки сохраняем
		lines = append(lines, line)
	}

	// Перезаписываем файл без удалённой строки
	err = os.WriteFile(filename, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	if err != nil {
		return err
	}

	return nil
}

func setquarantineProxyFromFile(filename string, proxy string) error {
	// Открываем файл для чтения
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Читаем содержимое файла построчно
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Проверяем, начинается ли строка с "peer " и содержит ли нужный прокси
		if strings.HasPrefix(line, "peer ") {
			existingProxy := strings.TrimSpace(strings.TrimPrefix(line, "peer "))
			if existingProxy == proxy {
				// Заменяем "peer" на "quarantine"
				line = strings.Replace(line, "peer ", "quarantine ", 1)
			}
		}

		// Также проверяем строки autoquarantine и переводим их в quarantine
		if strings.HasPrefix(line, "autoquarantine ") {
			existingProxy := strings.TrimSpace(strings.TrimPrefix(line, "autoquarantine "))
			if existingProxy == proxy {
				line = strings.Replace(line, "autoquarantine ", "quarantine ", 1)
			}
		}

		// Сохраняем строку (изменённую или нет)
		lines = append(lines, line)
	}

	// Перезаписываем файл с обновлённым содержимым
	err = os.WriteFile(filename, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	if err != nil {
		return err
	}

	return nil
}

func outquarantineProxyFromFile(filename string, proxy string) error {
	// Открываем файл для чтения
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Читаем содержимое файла построчно
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Проверяем, начинается ли строка с "quarantine "+proxy
		if strings.HasPrefix(line, "quarantine "+proxy) {
			// Заменяем "quarantine" на "peer"
			line = strings.Replace(line, "quarantine", "peer", 1)
		}

		// Сохраняем строку (изменённую или нет)
		lines = append(lines, line)
	}

	// Перезаписываем файл с обновлённым содержимым
	err = os.WriteFile(filename, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	if err != nil {
		return err
	}

	return nil
}

func addProxyToFile(filename string, proxy string) error {
	// Открываем файл в режиме дозаписи (Append), записи (Write) и создания при отсутствии (Create)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Проверяем, есть ли уже такая запись в файле
	exists, err := isProxyExistsInFile(filename, proxy)
	if err != nil {
		return fmt.Errorf("failed to check proxy existence: %w", err)
	}
	if exists {
		return fmt.Errorf("proxy '%s' already exists in the file", proxy)
	}

	// Добавляем прокси в файл в нужном формате
	_, err = file.WriteString(fmt.Sprintf("peer %s\n", proxy))
	if err != nil {
		return fmt.Errorf("failed to write proxy to file: %w", err)
	}

	return nil
}

func isProxyExistsInFile(filename string, proxy string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		expectedLine := "peer " + proxy
		if line == expectedLine {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil
}
