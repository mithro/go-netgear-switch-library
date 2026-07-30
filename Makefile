JAIL := ./scripts/jail.sh
GOLANGCI_VERSION := v2.3.0
GOLANGCI := ./bin/golangci-lint

.PHONY: fmt-check vet lint test cover tools

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(JAIL) go vet ./...

tools: $(GOLANGCI)
$(GOLANGCI):
	mkdir -p bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
	  | sh -s -- -b ./bin $(GOLANGCI_VERSION)

lint: tools
	$(JAIL) $(GOLANGCI) run

test:
	$(JAIL) go test -race ./...

cover:
	$(JAIL) go test -race -coverprofile=coverage.out ./...
	$(JAIL) go run ./scripts/coveragegate -profile coverage.out -min 90
