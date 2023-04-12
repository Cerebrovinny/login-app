.PHONY: test-register-admin migrate-server run-server build-docker

test-register-admin:
	@echo "Testing registerAdmin..."
	go test -v ./migration

migrate-server:
	@echo "Creating admin user and initializing the database..."
	ADMIN_USERNAME=admin ADMIN_PASSWORD=admin123 go run -mod=mod ./cmd/migrate/main.go

run-server:
	@echo "Starting the server..."
	MONGO_CONNECTION_STRING=mongodb://localhost:27017 MONGO_DATABASE_NAME=loginapp go run main.go

build-docker:
	@echo "Building Docker image..."
	docker build -t mongodb .

run-docker:
	@echo "Running MongoDB Docker container..."
	docker run -d --name mongodb -p 27017:27017 mongodb
