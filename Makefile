BIN := psdetect

.PHONY: build install test vet db clean

build:
	go build -o $(BIN) ./cmd/psdetect

install:
	go install ./cmd/psdetect

vet:
	go vet ./...

test:
	go test ./...

# Rebuild the embedded fingerprint DB. Point PS_REPO at a PrestaShop git clone.
db:
	python3 tooling/build_db.py

clean:
	rm -f $(BIN)
