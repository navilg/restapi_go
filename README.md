## Start http server

```
go run main.go
```

Server listens on port 30000

## Start https server

Get a TLS certificate from providers (e.g. Letsencrypt, AWS, etc.) and place it in tls directory.
Or, Generate self-signed TLS key and certificate.

```
mkdir -p tls
openssl genrsa -out "tls/tls.key" 2048
openssl req -new -x509 -sha256 -key "tls/tls.key" -out "tls/tls.crt" -days 7
```

Start server

```
go run main.go --tls=true
```

Server listens on port 30443.