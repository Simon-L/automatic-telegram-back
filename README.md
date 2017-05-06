# automatic-telegram-back
Automatic Telegram: a lightweight WYSIWYG for static content generators -- backend code written in Golang

```
$ go get
$ go run *.go
$ # or go build; ./automatic-telegram-back
```

Listens on `:8000` and proxies `/` to `localhost:9000` to use frontend development server (provided by `aurelia-cli`, see https://github.com/crucialhawg/automatic-telegram)

## Usage

Run with no argument to start the backend server:  
`go run *.go`

#### Adding users
Run with the `adduser` command to add a new site user:
`go run *.go adduser -name alice@example.com -domain www.example.com -backend hugo`
