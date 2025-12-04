-- Kong MinIO Gateway Plugin - Handler
-- Main plugin logic that intercepts requests and proxies them to MinIO
-- This plugin handles MinIO AWS Signature V4 signing

local http = require "resty.http"
local aws_v4 = require "kong.plugins.minio-gateway.aws_v4"

local MinioGatewayHandler = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

-- Helper function to build MinIO endpoint URL from Kong service
local function build_minio_endpoint(service)
  local protocol = service.protocol
  local host = service.host
  local port = service.port
  
  -- Standard ports don't need to be included
  if (protocol == "http" and port == 80) or (protocol == "https" and port == 443) then
    return string.format("%s://%s", protocol, host)
  else
    return string.format("%s://%s:%d", protocol, host, port)
  end
end

-- Helper function to extract host header from service
local function get_host_header(service)
  local host = service.host
  local port = service.port
  local protocol = service.protocol
  
  -- Standard ports don't need to be included in Host header
  if (protocol == "http" and port == 80) or (protocol == "https" and port == 443) then
    return host
  else
    return string.format("%s:%d", host, port)
  end
end

-- Main access phase handler
function MinioGatewayHandler:access(conf)
  kong.log.info("MinIO Gateway Plugin: Processing request")
  
  -- This plugin only handles AWS Signature V4 signing for MinIO
  
  -- Step 1: Get request details
  local method = kong.request.get_method()
  local path = kong.request.get_path()
  local query_string = kong.request.get_raw_query()
  local original_headers = kong.request.get_headers()
  local body = kong.request.get_raw_body() or ""
  
  kong.log.debug("Request method: ", method)
  kong.log.debug("Original path: ", path)
  
  -- Step 2: Process the path
  -- The plugin uses Kong's routing context to build the correct MinIO path
  -- Kong route handles strip_path logic
  -- We proxy directly using Kong's service configuration
  
  -- Get the service from the context
  local service = kong.router.get_service()
  
  if not service then
    kong.log.err("No service found in request context")
    return kong.response.exit(500, { message = "Internal server error: no service" })
  end
  
  -- Get the route information
  local route = kong.router.get_route()
  local route_strip_path = route and route.strip_path or false
  local route_paths = route and route.paths or {}
  
  kong.log.debug("Service path: ", service.path or "/")
  kong.log.debug("Route strip_path: ", route_strip_path)
  
  -- Calculate the path that will be sent to the service
  local request_path = path
  
  -- If route has strip_path=true, strip the route's path prefix
  if route_strip_path and #route_paths > 0 then
    local route_path = route_paths[1] -- Use first path pattern
    if path:sub(1, #route_path) == route_path then
      request_path = path:sub(#route_path + 1)
      if request_path == "" then
        request_path = "/"
      end
      kong.log.debug("Stripped route path '", route_path, "', remaining: ", request_path)
    end
  end
  
  -- If strip_path_pattern is configured, apply additional stripping
  if conf.strip_path_pattern and conf.strip_path_pattern ~= "" then
    request_path = request_path:gsub("^" .. conf.strip_path_pattern, "")
    kong.log.debug("Stripped additional pattern '", conf.strip_path_pattern, "', result: ", request_path)
  end
  
  -- Normalize request path: ensure starts with /
  if not request_path:match("^/") then
    request_path = "/" .. request_path
  end
  
  -- Build the final MinIO path
  -- If bucket_name is configured, we need to insert it between service_path and request_path
  -- Structure: /service_path/bucket_name/request_path
  -- Example: /minio/test/sample.txt (not /test/minio/sample.txt)
  
  local service_path = service.path or ""
  local minio_path
  
  if conf.bucket_name and conf.bucket_name ~= "" then
    kong.log.info("Bucket configured: '", conf.bucket_name, "', Request path: '", request_path, "'")
    
    -- Check if request_path already starts with /bucket_name
    local bucket_prefix = "/" .. conf.bucket_name
    local has_bucket_in_request = false
    
    if request_path == bucket_prefix then
      has_bucket_in_request = true
    elseif #request_path > #bucket_prefix then
      local prefix_part = request_path:sub(1, #bucket_prefix)
      local next_char = request_path:sub(#bucket_prefix + 1, #bucket_prefix + 1)
      if prefix_part == bucket_prefix and next_char == "/" then
        has_bucket_in_request = true
      end
    end
    
    if has_bucket_in_request then
      -- Bucket already in request path, use as-is
      kong.log.info("Bucket already in request path")
      minio_path = service_path .. request_path
    else
      -- Insert bucket between service_path and request_path
      kong.log.info("Inserting bucket into path")
      minio_path = service_path .. bucket_prefix .. request_path
    end
  else
    -- No bucket configured, concatenate directly
    kong.log.debug("No bucket_name configured, using request path as-is")
    minio_path = service_path .. request_path
  end
  
  -- Normalize: remove double slashes, ensure starts with /
  minio_path = minio_path:gsub("//+", "/")
  if not minio_path:match("^/") then
    minio_path = "/" .. minio_path
  end
  
  kong.log.info("Final MinIO path (for signing): ", minio_path)
  kong.log.debug("Query string: ", query_string or "none")
  
  -- Build full MinIO URI (path + query string for HTTP request)
  local minio_uri = minio_path
  if query_string and query_string ~= "" then
    minio_uri = minio_uri .. "?" .. query_string
  end
  
  kong.log.debug("Full MinIO URI (with query): ", minio_uri)
  
  -- Build MinIO endpoint from Kong service configuration
  local minio_endpoint = build_minio_endpoint(service)
  local minio_url = minio_endpoint .. minio_uri
  
  kong.log.debug("Full MinIO URL: ", minio_url)
  
  -- Step 3: Prepare headers for MinIO request
  local headers = {}
  
  -- Copy relevant headers (excluding any client auth headers from Kong)
  for k, v in pairs(original_headers) do
    local lower_k = k:lower()
    -- Skip authorization and host headers (we'll set new ones for MinIO)
    if lower_k ~= "authorization" and lower_k ~= "host" then
      headers[k] = v
    end
  end
  
  -- Set host header for MinIO from service configuration
  local minio_host_header = get_host_header(service)
  headers["Host"] = minio_host_header
  
  kong.log.debug("MinIO Host header: ", minio_host_header)
  
  -- Step 4: Create AWS Signature V4
  -- Pass the path without query string, and query string separately
  local signed_headers = aws_v4.sign_request(
    method,
    minio_path,  -- Path only, no query string
    query_string or "",  -- Query string passed separately
    headers,
    body or "",
    conf.minio_access_key,
    conf.minio_secret_key,
    conf.minio_region,
    "s3"
  )
  
  -- Merge signed headers with original headers
  local request_headers = {}
  for k, v in pairs(headers) do
    -- Skip hop-by-hop headers
    local k_lower = k:lower()
    if k_lower ~= "connection" and 
       k_lower ~= "keep-alive" and 
       k_lower ~= "proxy-authenticate" and 
       k_lower ~= "proxy-authorization" and 
       k_lower ~= "te" and 
       k_lower ~= "trailers" and 
       k_lower ~= "transfer-encoding" and 
       k_lower ~= "upgrade" then
      request_headers[k] = v
    end
  end
  
  -- Add signed headers (this will add Authorization, X-Amz-Date, X-Amz-Content-Sha256, and Host)
  for k, v in pairs(signed_headers) do
    request_headers[k] = v
  end
  
  kong.log.debug("Signed Authorization header: ", request_headers["Authorization"])
  
  -- Create HTTP client
  local httpc = http.new()
  httpc:set_timeout(conf.timeout)
  
  -- Make request to MinIO
  kong.log.info("Proxying to MinIO: ", minio_url)
  
  local res, err = httpc:request_uri(minio_url, {
    method = method,
    headers = request_headers,
    body = body,
    ssl_verify = false,
  })
  
  if not res then
    kong.log.err("Failed to connect to MinIO: ", err)
    return kong.response.exit(502, { message = "Failed to connect to MinIO", error = err })
  end
  
  kong.log.info("MinIO response status: ", res.status)
  
  -- Forward response headers
  local response_headers = {}
  for k, v in pairs(res.headers) do
    local k_lower = k:lower()
    -- Skip hop-by-hop headers
    if k_lower ~= "connection" and 
       k_lower ~= "keep-alive" and 
       k_lower ~= "transfer-encoding" then
      response_headers[k] = v
    end
  end
  
  -- Return response to client
  return kong.response.exit(res.status, res.body, response_headers)
end

return MinioGatewayHandler
