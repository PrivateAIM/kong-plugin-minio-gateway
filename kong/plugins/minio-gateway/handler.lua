-- Kong MinIO Gateway Plugin - Handler
-- Main plugin logic that intercepts requests and proxies them to MinIO
-- This plugin handles MinIO AWS Signature V4 signing

local MinioGatewayHandler = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}