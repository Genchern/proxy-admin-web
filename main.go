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

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/jet"
)

// ProxyFile связывает страну с файлом
type ProxyFile struct {
	File    string
	Country string
}

var proxyFiles = []ProxyFile{
	{"proxies/ru.txt", "Russia"},
	{"proxies/us.txt", "USA"},
}

var mu sync.Mutex

func main() {
	engine := jet.New("./templates", ".jet")
	app := fiber.New(fiber.Config{Views: engine})

	// Статика
	app.Static("/static", "./static")

	// Главная страница
	app.Get("/", dashboard)
	app.Post("/add-proxy", addProxy)
	app.Get("/delete/:country/:proxy", deleteProxy)
	app.Get("/quarantine/:country/:proxy", quarantineProxy)
	app.Get("/dequarantine/:country/:proxy", dequarantineProxy)

	// Запуск авто-карантина
	go autoQuarantineCheck()

	log.Println("Server started on http://localhost:3000")
	app.Listen(":3000")
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
		if strings.HasPrefix(line, "peer ") {
			result = append(result, strings.TrimPrefix(line, "peer "))
		}
		if strings.HasPrefix(line, "autoquarantine ") {
			result = append(result, "QUARANTINE "+strings.TrimPrefix(line, "autoquarantine "))
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

// handlers/proxy_handlers.go
func dashboard(c *fiber.Ctx) error {
	auth := c.Cookies("auth") != ""
	if !auth {
		c.Redirect("/")
	}

	proxyMap := make(map[string][]string)
	for _, pf := range proxyFiles {
		proxies, _ := getProxiesFromFile(pf.File)
		proxyMap[pf.Country] = proxies
	}

	return c.Render("index", fiber.Map{
		"Proxies": proxyMap,
	})
}

func deleteProxy(c *fiber.Ctx) error {
	country := c.Params("country")
	proxy := c.Params("proxy")
	for _, pf := range proxyFiles {
		if pf.Country == country {
			removeProxyFromFile(pf.File, proxy)
		}
	}
	return c.Redirect("/dashboard")
}

func quarantineProxy(c *fiber.Ctx) error {
	country := c.Params("country")
	proxy := c.Params("proxy")
	for _, pf := range proxyFiles {
		if pf.Country == country {
			setquarantineProxyFromFile(pf.File, proxy)
		}
	}
	return c.Redirect("/dashboard")
}

func dequarantineProxy(c *fiber.Ctx) error {
	country := c.Params("country")
	proxy := c.Params("proxy")
	for _, pf := range proxyFiles {
		if pf.Country == country {
			outquarantineProxyFromFile(pf.File, proxy)
		}
	}
	return c.Redirect("/dashboard")
}

func addProxy(c *fiber.Ctx) error {
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
	return c.Redirect("/")
}

func logs(c *fiber.Ctx) error {
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
