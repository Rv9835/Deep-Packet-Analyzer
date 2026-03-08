# Local Development Runbook

## Services Overview

The Deep Packet Analyzer uses Docker Compose to provide local infrastructure services.

### Starting Services

```bash
docker-compose up -d
```

This command starts three services:

## Service Ports & Credentials

### PostgreSQL
- **Host**: `localhost`
- **Port**: `5432`
- **Database**: `dpa_db`
- **Username**: `postgres`
- **Password**: `postgres`
- **Connection String**: `postgresql://postgres:postgres@localhost:5432/dpa_db`

### Redis
- **Host**: `localhost`
- **Port**: `6379`
- **Connection URL**: `redis://localhost:6379`
- **Authentication**: None (default)

### MinIO (S3-Compatible Object Storage)
- **Host**: `localhost`
- **Web Console**: `http://localhost:9001/minio`
- **API Port**: `9000`
- **AccessKey**: `minioadmin`
- **SecretKey**: `minioadmin`
- **Default Bucket**: `packets`
- **S3 Endpoint**: `http://localhost:9000`

## Environment Configuration

Copy `.env.example` to `.env` and adjust values as needed for local development:

```bash
cp .env.example .env
```

Default `.env.example` values are already configured for the Docker Compose stack.

## Verification & Smoke Tests

### Prerequisites
- Docker and Docker Compose installed
- `psql` CLI (PostgreSQL client) for database verification
- `redis-cli` for Redis verification
- AWS CLI (or MinIO client) for S3 verification

### 1. PostgreSQL Connectivity

```bash
psql postgresql://postgres:postgres@localhost:5432/dpa_db -c "SELECT 1"
```

Expected output:
```
 ?column?
----------
        1
(1 row)
```

### 2. Redis Connectivity

```bash
redis-cli -h localhost -p 6379 PING
```

Expected output:
```
PONG
```

### 3. MinIO Bucket & Upload/Download

#### Using AWS CLI

Set up MinIO profile (one-time):
```bash
aws configure --profile minio
# Access Key: minioadmin
# Secret Key: minioadmin
# Default region: us-east-1
# Output format: json
```

Create bucket:
```bash
aws --endpoint-url http://localhost:9000 --profile minio s3 mb s3://packets
```

Upload test file:
```bash
echo "test data" > /tmp/test.txt
aws --endpoint-url http://localhost:9000 --profile minio s3 cp /tmp/test.txt s3://packets/test.txt
```

Download test file:
```bash
aws --endpoint-url http://localhost:9000 --profile minio s3 cp s3://packets/test.txt /tmp/test-download.txt
cat /tmp/test-download.txt
```

#### Using MinIO CLI (mc)

Install MinIO client (if needed):
```bash
brew install minio-mc
```

Add MinIO host:
```bash
mc alias set minio http://localhost:9000 minioadmin minioadmin
```

Create bucket:
```bash
mc mb minio/packets
```

Upload test file:
```bash
echo "test data" > /tmp/test.txt
mc cp /tmp/test.txt minio/packets/test.txt
```

Download test file:
```bash
mc cp minio/packets/test.txt /tmp/test-download.txt
cat /tmp/test-download.txt
```

## Stopping Services

```bash
docker-compose down
```

## Viewing Service Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f postgres
docker-compose logs -f redis
docker-compose logs -f minio
```

## Viewing Volumes

Persistent data is stored in Docker volumes:

```bash
# List volumes
docker volume ls | grep dpa

# Inspect a volume
docker volume inspect deep-packet-analyzer_postgres_data
```

## Troubleshooting

### Services won't start
- Ensure Docker daemon is running (`open -a Docker` on macOS)
- Check for port conflicts: `lsof -i :5432`, `lsof -i :6379`, `lsof -i :9000`
- Clean up: `docker-compose down -v` (removes volumes)

### Database connection refused
- Verify Postgres is running: `docker-compose ps`
- Check logs: `docker-compose logs postgres`

### MinIO bucket not found
- Access MinIO console at `http://localhost:9001/minio` and create bucket manually
- Verify credentials are correct (minioadmin / minioadmin)

## Next Steps

Once services are running, you can:
1. Schema migrations (when database schema is defined)
2. Load test data into Postgres
3. Test packet analysis with pcap files in MinIO
4. Start the web and worker services against this infrastructure
