# test-goaway

A simple Go server that simulates HTTP/2 GOAWAY errors for testing purposes.

## Features

- **GOAWAY Simulation**: Sends HTTP/2 GOAWAY frames for `/chat/completions` requests
- **Proxy Pass-through**: Forwards all other requests to `https://api.githubcopilot.com`
- **HTTP/2 Support**: Full HTTP/2 support with TLS

## Building

```bash
go build -o server main.go
```

## Running

```bash
./server
```

The server will start on `https://localhost:8443` with a self-signed certificate.

## Usage

### Testing GOAWAY behavior

When you make a request to any `/chat/completions` endpoint (e.g., `https://localhost:8443/v1/chat/completions`), the server will:
- For HTTP/2 connections: Close the connection, which triggers a GOAWAY frame
- For HTTP/1.1 connections: Return a 503 Service Unavailable and close the connection

### Testing proxy pass-through

All other requests will be proxied to `https://api.githubcopilot.com`. For example:
- `https://localhost:8443/models` → `https://api.githubcopilot.com/models`
- `https://localhost:8443/v1/engines` → `https://api.githubcopilot.com/v1/engines`

## Notes

- The server uses a self-signed certificate, so you'll need to accept the certificate warning or use `-k` with curl
- Example curl command: `curl -k https://localhost:8443/chat/completions`
