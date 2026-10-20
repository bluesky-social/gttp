default: lint test

# Installs the required local development tools
install-tools:
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

# Run linter
lint:
    golangci-lint run

# Run tests
test *ARGS="./...":
    go test -count=1 {{ARGS}}

# Run tests with the race detector enabled
test-race *ARGS="./...":
    just test -race {{ARGS}}
