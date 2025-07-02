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
	"gopkg.in/yaml.v3"
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

type ProxyStats struct {
	Total   int `yaml:"total"`
	Success int `yaml:"success"`
}

var (
	statsMutex sync.RWMutex
	proxyStats = make(map[string]*ProxyStats)
)

// В начале файла main.go
type ProxyStatus struct {
	Proxy  string
	Status string // peer / quarantine / autoquarantine / locked
}

var (
	lockedProxies = make(map[string]bool) // proxy -> locked?
	lockMutex     sync.Mutex
)

var mu sync.Mutex

func main() {
	loadProxyFiles() // первый раз загружаем файлы

	err := loadLockedProxies()
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Не могу загрузить заблокированные прокси: %v", err)
	}

	// Создаём папку logs, если её нет
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		err := os.Mkdir("logs", 0755)
		if err != nil {
			log.Fatalf("Не могу создать папку logs: %v", err)
		}
	}

	// Создаём proxy_stats.yaml, если его нет
	if _, err := os.Stat("logs/proxy_stats.yaml"); os.IsNotExist(err) {
		emptyData, err := yaml.Marshal(map[string]ProxyStats{})
		if err != nil {
			log.Printf("Ошибка при создании пустого YAML: %v", err)
			return
		}
		err = os.WriteFile("logs/proxy_stats.yaml", emptyData, 0644)
		if err != nil {
			log.Printf("Ошибка при создании файла proxy_stats.yaml: %v", err)
		}
	}

	er := loadProxyStats() // загружаем статистику прокси
	if er != nil && !os.IsNotExist(er) {
		log.Printf("Не могу загрузить статистику прокси: %v", er)
	}
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
		if username == "admin" && password == "1111" {
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
	app.Get("/delete/:country/:proxy", deleteProxy)

	app.Get("/quarantine/:country/:proxy", quarantineProxy)

	app.Get("/dequarantine/:country/:proxy", dequarantineProxy)

	app.Get("/lock/:country/:proxy", lockProxy)

	app.Get("/unlock/:country/:proxy", unlockProxy)

	// Дашборд
	app.Get("/dashboard", dashboard)

	// Запуск авто-карантина (заглушка)
	go autoQuarantineCheck()

	// === Периодическое сохранение статистики ===
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				err := saveProxyStats()
				if err != nil {
					log.Printf("Ошибка сохранения статистики: %v", err)
				} else {
					log.Println("Статистика прокси успешно сохранена")
				}
			}
		}
	}()

	// Горутина для периодического сохранения заблокированных прокси
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			err := saveLockedProxies()
			if err != nil {
				log.Printf("Ошибка сохранения locked_proxies.yaml: %v", err)
			}
		}
	}()

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

func loadProxyStats() error {
	data, err := os.ReadFile("logs/proxy_stats.yaml")
	if err != nil {
		log.Printf("Не могу прочитать статистику: %v", err)
		return err
	}

	statsMutex.Lock()
	defer statsMutex.Unlock()

	var rawStats map[string]ProxyStats
	err = yaml.Unmarshal(data, &rawStats)
	if err != nil {
		log.Printf("Ошибка при парсинге YAML: %v", err)
		return err
	}

	proxyStats = make(map[string]*ProxyStats)
	for key, val := range rawStats {
		tmp := val
		proxyStats[key] = &tmp
	}

	return nil
}

func saveProxyStats() error {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	// Преобразуем карту указателей в карту структур для корректного YAML
	tempMap := make(map[string]ProxyStats)
	for key, val := range proxyStats {
		if val != nil {
			tempMap[key] = *val
		} else {
			tempMap[key] = ProxyStats{}
		}
	}

	data, err := yaml.Marshal(tempMap)
	if err != nil {
		return err
	}

	return os.WriteFile("logs/proxy_stats.yaml", data, 0644)
}

func getSuccessRate(proxy string) float64 {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	stats, ok := proxyStats[proxy]
	if !ok || stats == nil || stats.Total == 0 {
		return 0
	}
	return float64(stats.Success) / float64(stats.Total) * 100
}

// func autoQuarantineCheck() {
// 	ticker := time.NewTicker(10 * time.Second)
// 	defer ticker.Stop()
// 	for range ticker.C {
// 		statsMutex.RLock()
// 		// Получаем список всех прокси
// 		for _, pf := range proxyFiles {
// 			proxies, _ := getProxiesFromFile(pf.File)
// 			for _, proxy := range proxies {
// 				// Пропускаем прокси, которые в состоянии locked
// 				if isProxyLocked(proxy) {
// 					continue
// 				}

// 				if isUnreachable(proxy) {
// 					setAutoQuarantine(pf.File, proxy)
// 				} else {
// 					outAutoQuarantine(pf.File, proxy)
// 				}
// 			}
// 		}
// 		statsMutex.RUnlock()
// 	}
// }

func autoQuarantineCheck() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for _, pf := range proxyFiles {
			proxies, _ := getProxiesFromFile(pf.File)
			for _, proxy := range proxies {
				// Пропускаем прокси, которые в состоянии locked
				if isProxyLocked(proxy) {
					isUnreachable(proxy)
					continue
				}
				if isUnreachable(proxy) {
					setAutoQuarantine(pf.File, proxy)
				} else {
					outAutoQuarantine(pf.File, proxy)
				}
			}
		}
	}
}

// func autoQuarantineCheck() {
// 	ticker := time.NewTicker(30 * time.Second)
// 	defer ticker.Stop()

// 	for range ticker.C {
// 		for _, pf := range proxyFiles {
// 			proxies, _ := getProxiesFromFile(pf.File)
// 			for _, proxy := range proxies {
// 				if isUnreachable(proxy) {
// 					setAutoQuarantine(pf.File, proxy)
// 				} else {
// 					outAutoQuarantine(pf.File, proxy)
// 				}
// 			}
// 		}
// 	}
// }

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

	resp, err := client.Get("https://ipinfo.io/json ")

	statsMutex.Lock()
	defer statsMutex.Unlock()

	// Если прокси ещё не был в карте — добавляем его с нулевыми значениями
	if proxyStats[proxy] == nil {
		proxyStats[proxy] = &ProxyStats{}
	}

	// Увеличиваем общее число проверок
	proxyStats[proxy].Total++

	// Если ответ успешный — увеличиваем счётчик успехов
	if err == nil && resp.StatusCode == 200 {
		proxyStats[proxy].Success++
	} else {
		// Не увеличивай ошибки, просто оставь как есть
	}

	return err != nil || resp.StatusCode != 200
}

// func isUnreachable(proxy string) bool {
// 	proxyURL, err := url.Parse(proxy)
// 	if err != nil {
// 		return true
// 	}

// 	client := &http.Client{
// 		Transport: &http.Transport{
// 			Proxy:           http.ProxyURL(proxyURL),
// 			MaxIdleConns:    10,
// 			IdleConnTimeout: 5 * time.Second,
// 		},
// 		Timeout: 5 * time.Second,
// 	}

// 	resp, err := client.Get("https://ipinfo.io/json")
// 	if err != nil || resp.StatusCode != 200 {
// 		return true
// 	}
// 	return false
// }

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

// // handlers/proxy_handlers.go
// func dashboard(c fiber.Ctx) error {
// 	auth := c.Cookies("auth") != ""
// 	if !auth {
// 		return c.Redirect().To("/")
// 	}

// 	// Получаем сообщение из куки
// 	flashMsg := c.Cookies("flash", "")
// 	if flashMsg != "" {
// 		// Удаляем куку после чтения
// 		c.Cookie(&fiber.Cookie{
// 			Name:     "flash",
// 			Value:    "",
// 			Expires:  time.Now().Add(-time.Hour),
// 			HTTPOnly: true,
// 			SameSite: "Lax",
// 		})
// 	}

// 	proxyMap := make(map[string][]string)
// 	for _, pf := range proxyFiles {
// 		proxies, _ := getProxiesFromFile(pf.File)
// 		proxyMap[pf.Country] = proxies
// 	}

// 	var html strings.Builder

// 	html.WriteString(`<!DOCTYPE html>
// <html>
// <head>
// <meta charset="UTF-8">
// <title>Proxy Admin Panel</title>
// <link rel="stylesheet" href="/static/style.css">
// </head>
// <body>`)

// 	// Выводим сообщение, если оно есть
// 	if flashMsg != "" {
// 		html.WriteString(fmt.Sprintf(`
// <div id="flashMessage" style="
//     position: fixed;
//     top: 20px;
//     right: 20px;
//     background-color: #d4edda;
//     color: #155724;
//     padding: 10px 20px;
//     border-radius: 5px;
//     box-shadow: 0 2px 10px rgba(0,0,0,0.1);
//     z-index: 9999;
//     transition: opacity 0.5s;
// ">%s</div>
// <script>
//     setTimeout(function() {
//         var msg = document.getElementById('flashMessage');
//         if (msg) {
//             msg.style.opacity = '0';
//             setTimeout(function() { msg.remove(); }, 500);
//         }
//     }, 3000);
// </script>`, flashMsg))
// 	}

// 	html.WriteString(`
// <h1>Proxy List by Country</h1>

// <form method="POST" action="/add-proxy">
// <select name="country">`)
// 	filesMutex.RLock()
// 	for _, pf := range proxyFiles {
// 		html.WriteString(fmt.Sprintf(`<option value="%s">%s</option>`, pf.Country, pf.Country))
// 	}
// 	filesMutex.RUnlock()
// 	html.WriteString(`</select>
// <input type="text" name="proxy" placeholder="addr:port:user:pass or socks5://..." required>
// <select name="format">
// <option value="1">Format 1: addr:port:user:pass</option>
// <option value="2">Format 2: proto://addr:port:user:pass</option>
// <option value="3">Format 3: user:pass@addr:port</option>
// <option value="4">Format 4: proto://user:pass@addr:port</option>
// </select>
// <button type="submit">Add Proxy</button>
// </form>

// <h2>Add Country</h2>
// <form method="POST" action="/add-country">
// <input type="text" name="countryName" placeholder="Country Name (e.g., Germany)" required>
// <input type="text" name="countryCode" placeholder="Country Code (e.g., DE)" required>
// <button type="submit">Add Country</button>
// </form>
// `)

// 	for country, proxies := range proxyMap {
// 		html.WriteString(fmt.Sprintf("<h2>%s</h2><ul>", country))
// 		for _, proxy := range proxies {
// 			html.WriteString("<li>")

// 			if strings.HasPrefix(proxy, "autoquarantine ") {
// 				cleanProxy := proxy[14:] // убираем "autoquarantine "
// 				html.WriteString(fmt.Sprintf("🟡 Autoquarantined: %s <a href=\"/dequarantine/%s/%s\">Restore</a> <a href=\"/delete/%s/%s\">Delete</a>",
// 					cleanProxy, url.QueryEscape(country), url.QueryEscape(proxy), url.QueryEscape(country), url.QueryEscape(proxy)))
// 			} else if strings.HasPrefix(proxy, "quarantine ") {
// 				cleanProxy := proxy[11:] // убираем "quarantine "
// 				html.WriteString(fmt.Sprintf("🔴 Quarantined: %s <a href=\"/dequarantine/%s/%s\">Restore</a> <a href=\"/delete/%s/%s\">Delete</a>",
// 					cleanProxy, url.QueryEscape(country), url.QueryEscape(proxy), url.QueryEscape(country), url.QueryEscape(proxy)))
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

func dashboard(c fiber.Ctx) error {
	auth := c.Cookies("auth") != ""
	if !auth {
		return c.Redirect().To("/")
	}

	flashMsg := c.Cookies("flash", "")
	if flashMsg != "" {
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
<style>
.proxy-card {
    margin: 10px 0;
    padding: 10px;
    background-color: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.1);
    font-family: monospace;
	border-left: 4px solid rgb(28, 180, 49);
    white-space: nowrap;        /* Запрещаем перенос текста */
    width: 100%;                /* На всю ширину */
    max-width: 100%;
	font-size: 16px;
    overflow-x: auto;           /* Добавляем горизонтальный скролл при необходимости */
}
.proxy-card.quarantined {
    border-left: 4px solid #dc3545;
    color: #721c24;
    background-color: #f8d7da;
}
.proxy-card.autoquarantined {
    border-left: 4px solid #ffc107;
    color: #856404;
    background-color: #fff3cd;
}
.proxy-card.locked {
    border-left: 4px solid rgb(28, 180, 49);
    color: rgb(39, 38, 38);
    background-color: #fff;
}
/* SVG или Font Awesome для замка */
.lock-icon {
    width: 16px;
    height: 16px;
    vertical-align: middle;
    margin-right: 5px;
}
.proxy-url {
    display: block;
    font-size: 16px;
    word-break: break-all;     
    min-width: 300px;
}
.actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}
.btn {
    text-decoration: none;
    color: white;
    background-color: #007bff;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 14px;
    cursor: pointer;
}
.btn.quarantine {
    background-color: #ffc107; /* Жёлтый */
    color: #212529;
}
.btn.restore {
    background-color: #28a745; /* Зелёный */
}
.btn.delete {
    background-color: #dc3545; /* Красный */
}
.btn:hover {
    opacity: 0.9;
}

.btn.lock {
    background-color: #343a40;
}
.btn.unlock {
    background-color: #28a745;
}

.status-icon {
  vertical-align: middle;
  margin-right: 4px;
}

.status-icon.active circle {
  fill: lime; /* или #28a745 — зелёный */
}

.lock-icon {
  vertical-align: middle;
  margin-right: 4px;
}
// .stats {
//     position: absolute;
//     bottom: 8px;
//     right: 10px;
//     font-size: 14px;
//     color: #28a745;
//     font-weight: bold;
// }
</style>
</head>
<body>`)

	// Вывод флеш-сообщения (если есть)
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
</form>`)

	html.WriteString("<ul style=\"list-style: none; padding: 0; margin: 0; width: 33%;\">")

	for country, proxies := range proxyMap {
		html.WriteString(fmt.Sprintf("<h2>%s</h2><ul>", country))

		for _, proxy := range proxies {
			html.WriteString("<li style=\"width: 100%;\">")
			percentage := getSuccessRate(proxy)

			if isProxyLocked(proxy) {
				html.WriteString(fmt.Sprintf(`
<div class="proxy-card locked">
    <span class="proxy-url">🟢🔒 Activelocked: %s</span>
    <div class="actions">
        <a href="/quarantine/%s/%s" class="btn quarantine">Quarantine</a>
    	<a href="/delete/%s/%s" class="btn delete">Delete</a>
        <a href="/unlock/%s/%s" class="btn unlock">🔓 Unlock</a>
    </div>
	<div class="stats">✅ %.2f%%</div>
</div>`,
					proxy,
					url.QueryEscape(country), url.QueryEscape(proxy),
					url.QueryEscape(country), url.QueryEscape(proxy),
					url.QueryEscape(country), url.QueryEscape(proxy),
					percentage))

			} else if strings.HasPrefix(proxy, "autoquarantine ") {
				cleanProxy := proxy[14:] // убираем "autoquarantine "
				html.WriteString(fmt.Sprintf(`
<div class="proxy-card autoquarantined">
    <span class="proxy-url">🟡 Autoquarantined: %s</span>
    <div class="actions">
        <a href="/dequarantine/%s/%s" class="btn restore">Restore</a>
        <a href="/delete/%s/%s" class="btn delete">Delete</a>
		<a href="/lock/%s/%s" class="btn lock">🔒 Lock</a>
    </div>
	<div class="stats">✅ %.2f%%</div>
</div>`,
					cleanProxy,
					url.QueryEscape(country), url.QueryEscape(proxy),
					url.QueryEscape(country), url.QueryEscape(proxy),
					url.QueryEscape(country), url.QueryEscape(proxy),
					percentage))

			} else if strings.HasPrefix(proxy, "quarantine ") {
				cleanProxy := proxy[11:] // убираем "quarantine "
				html.WriteString(fmt.Sprintf(`
<div class="proxy-card quarantined">
    <span class="proxy-url">🔴 Quarantined: %s</span>
    <div class="actions">
        <a href="/dequarantine/%s/%s" class="btn restore">Restore</a>
        <a href="/delete/%s/%s" class="btn delete">Delete</a>
    </div>
</div>`,
					cleanProxy,
					url.QueryEscape(country), url.QueryEscape(proxy),
					url.QueryEscape(country), url.QueryEscape(proxy)))

			} else {
				html.WriteString(fmt.Sprintf(`
<div class="proxy-card">
    <span class="proxy-url">🟢 Active: %s</span>
    <div class="actions">
        <a href="/quarantine/%s/%s" class="btn quarantine">Quarantine</a>
        <a href="/delete/%s/%s" class="btn delete">Delete</a>
    </div>
	<div class="stats">✅ %.2f%%</div>
</div>`,
					proxy,
					url.QueryEscape(country), url.QueryEscape(proxy),
					url.QueryEscape(country), url.QueryEscape(proxy),
					percentage))
			}

			html.WriteString("</li>")
		}
		html.WriteString("</ul>")
	}

	html.WriteString(`</body></html>`)

	return c.Type("html", "utf-8").SendString(html.String())
}

func deleteProxy(c fiber.Ctx) error {
	country := c.Params("country")
	proxy := c.Params("proxy")
	fmt.Printf("Страна: %s | Прокси: %s", country, proxy)
	for _, pf := range proxyFiles {
		fmt.Printf("Файл: %s | Прокси: %s\n", pf.File, proxy)
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
	fmt.Printf("Обычный прокси: %s\n", proxy)
	decodedProxy, err := url.QueryUnescape(proxy)
	if err != nil {
		decodedProxy = proxy
	}

	decodedProxy = strings.TrimSpace(decodedProxy)
	fmt.Printf("Декодированный прокси: %s\n", decodedProxy)

	mu.Lock()
	defer mu.Unlock()

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

		// Проверяем строку на наличие любого из возможных префиксов и совпадение прокси
		if (strings.HasPrefix(line, "peer ") ||
			strings.HasPrefix(line, "quarantine ") ||
			strings.HasPrefix(line, "autoquarantine ")) &&
			strings.Contains(line, decodedProxy) {

			// Пропускаем эту строку — тем самым удаляем её
			continue
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
	// fmt.Printf("Обычный прокси: %s\n", proxy)
	decodedProxy, err := url.QueryUnescape(proxy)
	if err != nil {
		decodedProxy = proxy
	}

	decodedProxy = strings.TrimSpace(decodedProxy)
	fmt.Printf("Декодированный прокси: %s\n", decodedProxy)

	mu.Lock()
	defer mu.Unlock()

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
			if existingProxy == decodedProxy {
				// Заменяем "peer" на "quarantine"
				line = strings.Replace(line, "peer ", "quarantine ", 1)
			}
		}

		// Также проверяем строки autoquarantine и переводим их в quarantine
		if strings.HasPrefix(line, "autoquarantine ") {
			existingProxy := strings.TrimSpace(strings.TrimPrefix(line, "autoquarantine "))
			if existingProxy == decodedProxy {
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
	fmt.Printf("Обычный прокси: %s\n", proxy)
	decodedProxy, err := url.QueryUnescape(proxy)
	if err != nil {
		decodedProxy = proxy
	}

	decodedProxy = strings.TrimSpace(decodedProxy)
	fmt.Printf("Декодированный прокси: %s\n", decodedProxy)

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

		// Проверяем, является ли строка quarantine или autoquarantine и содержит нужный прокси
		if strings.HasPrefix(line, "quarantine ") &&
			strings.Contains(line, decodedProxy) {

			cleandecodedProxy := decodedProxy[11:] // убираем "quarantine "

			// Меняем префикс на peer
			lines = append(lines, "peer "+cleandecodedProxy)

		} else if strings.HasPrefix(line, "autoquarantine ") &&
			strings.Contains(line, decodedProxy) {

			cleandecodedProxy := decodedProxy[14:] // убираем "autoquarantine "

			// Меняем префикс на peer
			lines = append(lines, "peer "+cleandecodedProxy)
		} else {
			// Сохраняем все остальные строки как есть
			lines = append(lines, line)
		}

	}

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

func lockProxy(c fiber.Ctx) error {
	country := c.Params("country")
	proxy := c.Params("proxy")

	decodedProxy, err := url.QueryUnescape(proxy)
	if err != nil {
		decodedProxy = proxy
	}

	// Убираем возможные префиксы
	cleanProxy := decodedProxy
	if strings.HasPrefix(decodedProxy, "autoquarantine ") {
		cleanProxy = strings.TrimSpace(strings.TrimPrefix(decodedProxy, "autoquarantine "))
	} else if strings.HasPrefix(decodedProxy, "quarantine ") {
		cleanProxy = strings.TrimSpace(strings.TrimPrefix(decodedProxy, "quarantine "))
	}

	for _, pf := range proxyFiles {
		if pf.Country == country {
			err := setProxyToPeer(pf.File, cleanProxy)
			if err != nil {
				log.Printf("Ошибка перевода в peer: %v", err)
			} else {
				lockMutex.Lock()
				lockedProxies[cleanProxy] = true // ✅ Чистый адрес
				lockMutex.Unlock()

				err = saveLockedProxies()
				if err != nil {
					log.Printf("Ошибка сохранения locked_proxies.yaml: %v", err)
				} else {
					log.Println("locked_proxies.yaml успешно обновлён")
				}
			}
		}
	}

	return c.Redirect().To("/dashboard")
}

// func unlockProxy(c fiber.Ctx) error {
// 	country := c.Params("country")
// 	proxy := c.Params("proxy")

// 	for _, pf := range proxyFiles {
// 		if pf.Country == country {
// 			setAutoQuarantine(pf.File, proxy)
// 		}
// 	}

// 	lockMutex.Lock()
// 	delete(lockedProxies, proxy)
// 	lockMutex.Unlock()

// 	return c.Redirect().To("/dashboard")
// }

func unlockProxy(c fiber.Ctx) error {
	// country := c.Params("country")
	proxy := c.Params("proxy")

	decodedProxy, err := url.QueryUnescape(proxy)
	if err != nil {
		decodedProxy = proxy
	}

	// Убираем возможные префиксы
	cleanProxy := decodedProxy
	if strings.HasPrefix(decodedProxy, "autoquarantine ") {
		cleanProxy = strings.TrimSpace(strings.TrimPrefix(decodedProxy, "autoquarantine "))
	} else if strings.HasPrefix(decodedProxy, "quarantine ") {
		cleanProxy = strings.TrimSpace(strings.TrimPrefix(decodedProxy, "quarantine "))
	}

	// УДАЛЯЕМ прокси из locked_proxies.yaml
	lockMutex.Lock()
	delete(lockedProxies, cleanProxy) // удаляем по чистому адресу
	lockMutex.Unlock()

	// СОХРАНЯЕМ обновлённый список
	err = saveLockedProxies()
	if err != nil {
		log.Printf("Ошибка сохранения locked_proxies.yaml: %v", err)
	}

	return c.Redirect().To("/dashboard")
}

func setProxyToPeer(filename string, proxy string) error {
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
		if strings.HasPrefix(line, "autoquarantine ") || strings.HasPrefix(line, "quarantine ") {
			existingProxy := strings.TrimSpace(strings.TrimPrefix(line, "autoquarantine "))
			existingProxy = strings.TrimSpace(strings.TrimPrefix(existingProxy, "quarantine "))

			if existingProxy == proxy {
				lines = append(lines, "peer "+proxy)
				continue
			}
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return os.WriteFile(filename, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func isProxyLocked(proxy string) bool {
	lockMutex.Lock()
	defer lockMutex.Unlock()
	_, ok := lockedProxies[proxy]
	return ok
}

func saveLockedProxies() error {
	lockMutex.Lock()
	defer lockMutex.Unlock()

	data, err := yaml.Marshal(lockedProxies)
	// fmt.Print(data)
	if err != nil {
		return err
	}

	return os.WriteFile("logs/locked_proxies.yaml", data, 0644)
}

func loadLockedProxies() error {
	data, err := os.ReadFile("logs/locked_proxies.yaml")
	if err != nil {
		log.Printf("Не могу прочитать locked_proxies.yaml: %v", err)
		return err
	}

	lockMutex.Lock()
	defer lockMutex.Unlock()

	var loaded map[string]bool
	err = yaml.Unmarshal(data, &loaded)
	if err != nil {
		log.Printf("Ошибка при разборе YAML: %v", err)
		return err
	}

	lockedProxies = loaded
	return nil
}
