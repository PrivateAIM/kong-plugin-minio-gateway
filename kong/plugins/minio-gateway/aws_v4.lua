-- AWS Signature Version 4 Implementation for MinIO/S3
-- This module handles the cryptographic signing of requests

local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local ffi = require "ffi"

local _M = {}

-- Load OpenSSL HMAC functions via FFI
ffi.cdef[[
typedef struct engine_st ENGINE;
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct hmac_ctx_st HMAC_CTX;

unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len);

const EVP_MD *EVP_sha256(void);
]]

local C = ffi.C
local EVP_sha256 = C.EVP_sha256

-- Helper function to compute SHA256 hash
local function sha256(data)
  local sha = resty_sha256:new()
  sha:update(data or "")
  local digest = sha:final()
  return str.to_hex(digest)
end

-- Helper function to compute HMAC-SHA256 using OpenSSL via FFI
local function hmac_sha256(key, data)
  local digest = ffi.new("unsigned char[32]")
  local digest_len = ffi.new("unsigned int[1]")
  
  C.HMAC(EVP_sha256(), key, #key, ffi.cast("const unsigned char*", data), #data, digest, digest_len)
  
  return ffi.string(digest, digest_len[0])
end

-- Helper function to get current timestamp
local function get_timestamp()
  return os.date("!%Y%m%dT%H%M%SZ", os.time())
end

-- Helper function to get current date
local function get_date()
  return os.date("!%Y%m%d", os.time())
end

-- Helper function to create canonical headers
local function get_canonical_headers(headers, signed_header_names)
  local canonical = {}
  
  for _, name in ipairs(signed_header_names) do
    -- Look up header case-insensitively
    local value = nil
    for k, v in pairs(headers) do
      if k:lower() == name:lower() then
        value = v
        break
      end
    end
    
    if value then
      -- Convert header name to lowercase and trim values
      local canonical_name = name:lower()
      local canonical_value = tostring(value):gsub("^%s*(.-)%s*$", "%1")
      table.insert(canonical, canonical_name .. ":" .. canonical_value)
    end
  end
  
  table.sort(canonical)
  return table.concat(canonical, "\n") .. "\n"
end

-- Helper function to create signed headers list
local function get_signed_headers(signed_header_names)
  local headers = {}
  for _, name in ipairs(signed_header_names) do
    table.insert(headers, name:lower())
  end
  table.sort(headers)
  return table.concat(headers, ";")
end

-- Helper function to URI encode for AWS (RFC 3986)
local function uri_encode(str)
  if not str then return "" end
  -- AWS Signature V4 uses RFC 3986 encoding
  -- Unreserved characters: A-Z, a-z, 0-9, hyphen (-), underscore (_), period (.), and tilde (~)
  str = string.gsub(str, "([^%w%-%.%_%~])",
    function(c) return string.format("%%%02X", string.byte(c)) end)
  return str
end

-- Helper function to create canonical query string
-- AWS Signature V4 requires query parameters to be:
-- 1. URI-encoded
-- 2. Sorted by parameter name
-- 3. In format: key1=value1&key2=value2
local function get_canonical_query_string(query_string)
  if not query_string or query_string == "" then
    return ""
  end
  
  -- Parse query string into key-value pairs
  local params = {}
  for pair in string.gmatch(query_string, "[^&]+") do
    local key, value = string.match(pair, "([^=]+)=?(.*)")
    if key then
      -- URI encode both key and value
      local encoded_key = uri_encode(key)
      local encoded_value = uri_encode(value)
      table.insert(params, {key = encoded_key, value = encoded_value})
    end
  end
  
  -- Sort by encoded key name
  table.sort(params, function(a, b) return a.key < b.key end)
  
  -- Build canonical query string
  local canonical_parts = {}
  for _, param in ipairs(params) do
    if param.value == "" then
      table.insert(canonical_parts, param.key .. "=")
    else
      table.insert(canonical_parts, param.key .. "=" .. param.value)
    end
  end
  
  return table.concat(canonical_parts, "&")
end

-- Main signing function
function _M.sign_request(method, uri, query_string, headers, body, access_key, secret_key, region, service)
  local timestamp = get_timestamp()
  local date = get_date()
  
  -- Prepare headers
  local request_headers = {}
  for k, v in pairs(headers) do
    request_headers[k] = v
  end
  
  -- Add required headers
  request_headers["X-Amz-Date"] = timestamp
  
  -- Compute content hash
  local content_hash = sha256(body)
  request_headers["X-Amz-Content-Sha256"] = content_hash
  
  -- Determine signed headers (we'll sign host, x-amz-* headers, and content-type if present)
  local signed_header_names = { "host", "x-amz-date", "x-amz-content-sha256" }
  -- Check for Content-Type case-insensitively
  for k, v in pairs(headers) do
    if k:lower() == "content-type" then
      table.insert(signed_header_names, "content-type")
      break
    end
  end
  
  -- Create canonical request
  local canonical_uri = uri
  local canonical_query = get_canonical_query_string(query_string)
  local canonical_headers = get_canonical_headers(request_headers, signed_header_names)
  local signed_headers = get_signed_headers(signed_header_names)
  
  -- AWS Signature V4 canonical request format:
  -- HTTPMethod\nCanonicalURI\nCanonicalQueryString\nCanonicalHeaders\n\nSignedHeaders\nHashedPayload
  -- Note: CanonicalHeaders must end with \n (which it does from get_canonical_headers)
  local canonical_request = method .. "\n" ..
                            canonical_uri .. "\n" ..
                            canonical_query .. "\n" ..
                            canonical_headers ..            -- already ends with \n
                            "\n" ..                          -- blank line separator
                            signed_headers .. "\n" ..
                            content_hash
  
  -- Create string to sign
  local credential_scope = date .. "/" .. region .. "/" .. service .. "/aws4_request"
  local string_to_sign = table.concat({
    "AWS4-HMAC-SHA256",
    timestamp,
    credential_scope,
    sha256(canonical_request)
  }, "\n")
  
  -- Calculate signature
  local k_date = hmac_sha256("AWS4" .. secret_key, date)
  local k_region = hmac_sha256(k_date, region)
  local k_service = hmac_sha256(k_region, service)
  local k_signing = hmac_sha256(k_service, "aws4_request")
  local signature = str.to_hex(hmac_sha256(k_signing, string_to_sign))
  
  -- Create authorization header
  local authorization = "AWS4-HMAC-SHA256 " ..
    "Credential=" .. access_key .. "/" .. credential_scope .. ", " ..
    "SignedHeaders=" .. signed_headers .. ", " ..
    "Signature=" .. signature
  
  request_headers["Authorization"] = authorization
  
  return request_headers
end

return _M
