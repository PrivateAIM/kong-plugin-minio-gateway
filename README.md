# Kong MinIO Gateway Plugin

A Kong plugin that acts as a gateway to MinIO (or S3-compatible storage). It intercepts incoming requests, signs them using AWS Signature Version 4, and proxies them to the MinIO server. This allows clients to access MinIO buckets without needing to pass AWS credentials directly. 

## Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `minio_access_key` | string | Yes | - | MinIO/S3 access key for AWS Signature V4. |
| `minio_secret_key` | string | Yes | - | MinIO/S3 secret key for AWS Signature V4. |
| `minio_region` | string | No | `us-east-1` | AWS region for Signature V4. |
| `bucket_name` | string | No | - | Specific MinIO/S3 bucket name. If not provided, the plugin assumes the bucket is part of the request path. |
| `timeout` | number | No | `100000` | Request timeout in milliseconds. |
| `strip_path_pattern` | string | No | - | Additional regex pattern to strip from the request path (e.g., `/s3`). |

## How it Works

1. **Intercept**: The plugin intercepts the request in the access phase.
2. **Path Processing**: It calculates the target path by stripping the route's path and any configured `strip_path_pattern`.
3. **Signing**: It constructs the canonical request, calculates the AWS Signature V4 using the configured credentials, and generates the `Authorization` header.
4. **Proxy**: The request is forwarded to the MinIO server with the correct authentication headers (`Authorization`, `x-amz-date`, `x-amz-content-sha256`).

