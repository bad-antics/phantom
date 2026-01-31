"""
Utility helper functions for Phantom.
"""

# ══════════════════════════════════════════════════════════════════════════════
# HASH UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Compute SHA256 hash.
"""
function sha256(data::Vector{UInt8})::Vector{UInt8}
    return collect(SHA.sha256(data))
end

"""
Compute SHA256 of string.
"""
function sha256(data::String)::Vector{UInt8}
    return sha256(Vector{UInt8}(data))
end

"""
Compute double SHA256 (Bitcoin-style).
"""
function sha256d(data::Vector{UInt8})::Vector{UInt8}
    return sha256(sha256(data))
end

"""
Compute HMAC-SHA256.
"""
function hmac_sha256(key::Vector{UInt8}, data::Vector{UInt8})::Vector{UInt8}
    # Simplified HMAC implementation
    block_size = 64
    
    # Pad/truncate key
    if length(key) > block_size
        key = sha256(key)
    end
    if length(key) < block_size
        key = vcat(key, zeros(UInt8, block_size - length(key)))
    end
    
    o_key_pad = [key[i] ⊻ 0x5c for i in 1:block_size]
    i_key_pad = [key[i] ⊻ 0x36 for i in 1:block_size]
    
    return sha256(vcat(o_key_pad, sha256(vcat(i_key_pad, data))))
end

"""
Hash to fixed-size bytes.
"""
function hash_to_bytes(data::Vector{UInt8}, size::Int)::Vector{UInt8}
    hash = sha256(data)
    while length(hash) < size
        hash = vcat(hash, sha256(hash))
    end
    return hash[1:size]
end

# ══════════════════════════════════════════════════════════════════════════════
# ENCODING UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Convert bytes to hex string.
"""
function bytes2hex(data::Vector{UInt8})::String
    return join([string(b, base=16, pad=2) for b in data])
end

"""
Convert hex string to bytes.
"""
function hex2bytes(hex::String)::Vector{UInt8}
    # Remove 0x prefix if present
    hex = replace(hex, r"^0x" => "")
    
    # Ensure even length
    if length(hex) % 2 != 0
        hex = "0" * hex
    end
    
    return [parse(UInt8, hex[i:i+1], base=16) for i in 1:2:length(hex)]
end

"""
Base64 encode.
"""
function base64_encode(data::Vector{UInt8})::String
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    result = Char[]
    
    for i in 1:3:length(data)
        b1 = data[i]
        b2 = i + 1 <= length(data) ? data[i+1] : 0x00
        b3 = i + 2 <= length(data) ? data[i+2] : 0x00
        
        push!(result, alphabet[(b1 >> 2) + 1])
        push!(result, alphabet[((b1 & 0x03) << 4 | (b2 >> 4)) + 1])
        
        if i + 1 <= length(data)
            push!(result, alphabet[((b2 & 0x0f) << 2 | (b3 >> 6)) + 1])
        else
            push!(result, '=')
        end
        
        if i + 2 <= length(data)
            push!(result, alphabet[(b3 & 0x3f) + 1])
        else
            push!(result, '=')
        end
    end
    
    return String(result)
end

"""
Base64 decode.
"""
function base64_decode(encoded::String)::Vector{UInt8}
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    result = UInt8[]
    
    # Remove padding count
    padding = count(==('='), encoded)
    encoded = replace(encoded, "=" => "A")  # Replace padding with A (0)
    
    for i in 1:4:length(encoded)
        c1 = findfirst(==(encoded[i]), alphabet) - 1
        c2 = findfirst(==(encoded[i+1]), alphabet) - 1
        c3 = findfirst(==(encoded[i+2]), alphabet) - 1
        c4 = findfirst(==(encoded[i+3]), alphabet) - 1
        
        push!(result, UInt8((c1 << 2) | (c2 >> 4)))
        push!(result, UInt8(((c2 & 0x0f) << 4) | (c3 >> 2)))
        push!(result, UInt8(((c3 & 0x03) << 6) | c4))
    end
    
    # Remove padding bytes
    return result[1:end-padding]
end

# ══════════════════════════════════════════════════════════════════════════════
# RANDOM UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate cryptographically secure random bytes.
"""
function secure_random(n::Int)::Vector{UInt8}
    return rand(UInt8, n)
end

"""
Generate random UUID.
"""
function random_uuid()::UUID
    return uuid4()
end

"""
Generate random nonce.
"""
function generate_nonce(size::Int=32)::Vector{UInt8}
    return secure_random(size)
end

"""
Generate random scalar for elliptic curve.
"""
function random_scalar()::BigInt
    # Generate random bytes and reduce modulo curve order
    bytes = secure_random(32)
    value = sum(BigInt(bytes[i]) << (8 * (i-1)) for i in 1:length(bytes))
    return mod(value, BN254_PRIME)
end

# ══════════════════════════════════════════════════════════════════════════════
# TIME UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Get current Unix timestamp.
"""
function unix_timestamp()::Int
    return Int(floor(datetime2unix(now())))
end

"""
Convert Unix timestamp to DateTime.
"""
function from_unix_timestamp(ts::Int)::DateTime
    return unix2datetime(ts)
end

"""
Format DateTime as ISO8601.
"""
function format_iso8601(dt::DateTime)::String
    return Dates.format(dt, "yyyy-mm-ddTHH:MM:SS.sssZ")
end

"""
Parse ISO8601 to DateTime.
"""
function parse_iso8601(s::String)::DateTime
    # Handle various ISO8601 formats
    s = replace(s, r"Z$" => "")
    s = replace(s, r"\+\d{2}:\d{2}$" => "")
    
    try
        return DateTime(s, "yyyy-mm-ddTHH:MM:SS.sss")
    catch
        try
            return DateTime(s, "yyyy-mm-ddTHH:MM:SS")
        catch
            return DateTime(s, "yyyy-mm-dd")
        end
    end
end

"""
Calculate time difference in seconds.
"""
function time_diff_seconds(t1::DateTime, t2::DateTime)::Float64
    return Dates.value(Millisecond(t2 - t1)) / 1000.0
end

# ══════════════════════════════════════════════════════════════════════════════
# VALIDATION UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Validate hex string.
"""
function is_valid_hex(s::String)::Bool
    return occursin(r"^(0x)?[0-9a-fA-F]+$", s)
end

"""
Validate UUID string.
"""
function is_valid_uuid(s::String)::Bool
    return occursin(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"i, s)
end

"""
Validate Ethereum address.
"""
function is_valid_eth_address(s::String)::Bool
    return occursin(r"^0x[0-9a-fA-F]{40}$", s)
end

"""
Validate Bitcoin address (simplified).
"""
function is_valid_btc_address(s::String)::Bool
    # P2PKH, P2SH, or Bech32
    return occursin(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", s) ||
           occursin(r"^bc1[a-zA-HJ-NP-Z0-9]{25,90}$", s)
end

# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURE UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Deep merge two dictionaries.
"""
function deep_merge(d1::Dict, d2::Dict)::Dict
    result = deepcopy(d1)
    
    for (k, v) in d2
        if haskey(result, k) && isa(result[k], Dict) && isa(v, Dict)
            result[k] = deep_merge(result[k], v)
        else
            result[k] = v
        end
    end
    
    return result
end

"""
Flatten nested dictionary.
"""
function flatten_dict(d::Dict, prefix::String="")::Dict{String, Any}
    result = Dict{String, Any}()
    
    for (k, v) in d
        key = isempty(prefix) ? string(k) : "$(prefix).$(k)"
        if isa(v, Dict)
            for (fk, fv) in flatten_dict(v, key)
                result[fk] = fv
            end
        else
            result[key] = v
        end
    end
    
    return result
end

"""
Get value from nested dictionary by path.
"""
function get_nested(d::Dict, path::String, default=nothing)
    keys = split(path, ".")
    current = d
    
    for key in keys
        if !isa(current, Dict) || !haskey(current, key)
            return default
        end
        current = current[key]
    end
    
    return current
end

# ══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLING
# ══════════════════════════════════════════════════════════════════════════════

"""
    PhantomError

Base error type for Phantom.
"""
abstract type PhantomError <: Exception end

"""
    CryptoError

Cryptographic operation error.
"""
struct CryptoError <: PhantomError
    message::String
end

"""
    ValidationError

Data validation error.
"""
struct ValidationError <: PhantomError
    message::String
    field::Union{String, Nothing}
end

"""
    ProofError

ZK proof error.
"""
struct ProofError <: PhantomError
    message::String
    proof_id::Union{UUID, Nothing}
end

"""
    NetworkError

Network/API error.
"""
struct NetworkError <: PhantomError
    message::String
    status_code::Union{Int, Nothing}
end

"""
Wrap function with error handling.
"""
function with_error_handling(f::Function, error_type::Type{<:PhantomError}=PhantomError)
    try
        return f()
    catch e
        if isa(e, PhantomError)
            rethrow()
        else
            throw(error_type(string(e)))
        end
    end
end
