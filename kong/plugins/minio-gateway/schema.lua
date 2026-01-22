-- Kong MinIO Gateway Plugin - Schema Definition
-- This file defines the configuration schema for the plugin

local typedefs = require "kong.db.schema.typedefs"

return {
  name = "minio-gateway",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {          
          -- MinIO Credentials (per service/bucket)
          -- Note: Host, port, and protocol are configured in Kong Service, not here
          { minio_access_key = {
              type = "string",
              required = true,
              description = "MinIO/S3 access key for AWS Signature V4"
          }},
          { minio_secret_key = {
              type = "string",
              required = true,
              description = "MinIO/S3 secret key for AWS Signature V4"
          }},
          { minio_region = {
              type = "string",
              default = "us-east-1",
              description = "AWS region for Signature V4 (usually us-east-1 for MinIO)"
          }},
          { bucket_name = {
              type = "string",
              required = false,
              description = "MinIO/S3 bucket name. If not provided, assumes bucket is in the request path"
          }},          
          { timeout = {
              type = "number",
              default = 100000,
              description = "Request timeout in milliseconds"
          }},
          { strip_path_pattern = {
              type = "string",
              required = false,
              description = "Additional path pattern to strip from requests (e.g., '/s3')"
          }},
        },
    }},
  },
}
