"""
Serialization utilities for Phantom.
"""

# ══════════════════════════════════════════════════════════════════════════════
# JSON SERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Serialize ZK proof to JSON-compatible Dict.
"""
function serialize_zk_proof(proof::ZKProof)::Dict{String, Any}
    return Dict{String, Any}(
        "proof_id" => string(proof.proof_id),
        "timestamp" => format_iso8601(proof.timestamp),
        "a" => serialize_point_dict(proof.a),
        "b" => serialize_point_dict(proof.b),
        "c" => serialize_point_dict(proof.c),
        "public_inputs" => [serialize_field_element(fe) for fe in proof.public_inputs]
    )
end

"""
Deserialize ZK proof from Dict.
"""
function deserialize_zk_proof(data::Dict{String, Any})::ZKProof
    return ZKProof(
        deserialize_point_dict(data["a"]),
        deserialize_point_dict(data["b"]),
        deserialize_point_dict(data["c"]),
        [deserialize_field_element(fe) for fe in data["public_inputs"]],
        parse_iso8601(data["timestamp"]),
        UUID(data["proof_id"])
    )
end

"""
Serialize vulnerability commitment to JSON-compatible Dict.
"""
function serialize_commitment(commitment::VulnerabilityCommitment)::Dict{String, Any}
    return Dict{String, Any}(
        "commitment_id" => string(commitment.commitment_id),
        "created_at" => format_iso8601(commitment.created_at),
        "severity_commitment" => bytes2hex(commitment.severity_commitment),
        "type_commitment" => bytes2hex(commitment.type_commitment),
        "description_commitment" => bytes2hex(commitment.description_commitment),
        "proof_commitment" => bytes2hex(commitment.proof_commitment),
        "metadata_hash" => bytes2hex(commitment.metadata_hash),
        "zk_proof" => isnothing(commitment.zk_proof) ? nothing : serialize_zk_proof(commitment.zk_proof)
    )
end

"""
Deserialize vulnerability commitment from Dict.
"""
function deserialize_commitment(data::Dict{String, Any})::VulnerabilityCommitment
    return VulnerabilityCommitment(
        UUID(data["commitment_id"]),
        parse_iso8601(data["created_at"]),
        hex2bytes(data["severity_commitment"]),
        hex2bytes(data["type_commitment"]),
        hex2bytes(data["description_commitment"]),
        hex2bytes(data["proof_commitment"]),
        hex2bytes(data["metadata_hash"]),
        isnothing(get(data, "zk_proof", nothing)) ? nothing : deserialize_zk_proof(data["zk_proof"])
    )
end

"""
Serialize disclosure policy to JSON-compatible Dict.
"""
function serialize_disclosure_policy(policy::DisclosurePolicy)::Dict{String, Any}
    return Dict{String, Any}(
        "policy_id" => string(policy.policy_id),
        "name" => policy.name,
        "description" => policy.description,
        "vendor_notify_delay" => Dates.value(Millisecond(policy.vendor_notify_delay)),
        "partial_disclosure_delay" => Dates.value(Millisecond(policy.partial_disclosure_delay)),
        "full_disclosure_delay" => Dates.value(Millisecond(policy.full_disclosure_delay)),
        "requires_vendor_response" => policy.requires_vendor_response,
        "allows_early_disclosure" => policy.allows_early_disclosure,
        "max_extension" => Dates.value(Millisecond(policy.max_extension))
    )
end

"""
Deserialize disclosure policy from Dict.
"""
function deserialize_disclosure_policy(data::Dict{String, Any})::DisclosurePolicy
    return DisclosurePolicy(
        UUID(data["policy_id"]),
        data["name"],
        data["description"],
        Millisecond(data["vendor_notify_delay"]),
        Millisecond(data["partial_disclosure_delay"]),
        Millisecond(data["full_disclosure_delay"]),
        data["requires_vendor_response"],
        data["allows_early_disclosure"],
        Millisecond(data["max_extension"])
    )
end

"""
Serialize audit trail to JSON-compatible Dict.
"""
function serialize_audit_trail(trail::AuditTrail)::Dict{String, Any}
    return Dict{String, Any}(
        "trail_id" => string(trail.trail_id),
        "created_at" => format_iso8601(trail.created_at),
        "events" => [serialize_audit_event(e) for e in trail.events],
        "merkle_root" => bytes2hex(trail.merkle_root),
        "chain_hash" => bytes2hex(trail.chain_hash),
        "witness_count" => length(trail.witness_signatures)
    )
end

"""
Serialize audit event to JSON-compatible Dict.
"""
function serialize_audit_event(event::AuditEvent)::Dict{String, Any}
    return Dict{String, Any}(
        "event_id" => string(event.event_id),
        "event_type" => string(event.event_type),
        "timestamp" => format_iso8601(event.timestamp),
        "subject_id" => string(event.subject_id),
        "actor_commitment" => bytes2hex(event.actor_commitment),
        "action_hash" => bytes2hex(event.action_hash),
        "previous_event_hash" => bytes2hex(event.previous_event_hash),
        "event_hash" => bytes2hex(event.event_hash)
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# BINARY SERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Serialize ZK proof to bytes.
"""
function serialize_proof_binary(proof::ZKProof)::Vector{UInt8}
    buffer = UInt8[]
    
    # Version byte
    push!(buffer, 0x01)
    
    # Proof ID (16 bytes)
    append!(buffer, serialize_uuid(proof.proof_id))
    
    # Timestamp (8 bytes)
    append!(buffer, serialize_timestamp(proof.timestamp))
    
    # Points A, B, C (64 bytes each)
    append!(buffer, serialize_point_binary(proof.a))
    append!(buffer, serialize_point_binary(proof.b))
    append!(buffer, serialize_point_binary(proof.c))
    
    # Public inputs count (4 bytes)
    append!(buffer, serialize_uint32(length(proof.public_inputs)))
    
    # Public inputs (32 bytes each)
    for fe in proof.public_inputs
        append!(buffer, serialize_field_element_binary(fe))
    end
    
    return buffer
end

"""
Deserialize ZK proof from bytes.
"""
function deserialize_proof_binary(data::Vector{UInt8})::ZKProof
    offset = 1
    
    # Version
    version = data[offset]
    offset += 1
    
    if version != 0x01
        throw(ValidationError("Unsupported proof version: $version", "version"))
    end
    
    # Proof ID
    proof_id = deserialize_uuid(data[offset:offset+15])
    offset += 16
    
    # Timestamp
    timestamp = deserialize_timestamp(data[offset:offset+7])
    offset += 8
    
    # Points
    a = deserialize_point_binary(data[offset:offset+63])
    offset += 64
    b = deserialize_point_binary(data[offset:offset+63])
    offset += 64
    c = deserialize_point_binary(data[offset:offset+63])
    offset += 64
    
    # Public inputs count
    count = deserialize_uint32(data[offset:offset+3])
    offset += 4
    
    # Public inputs
    public_inputs = FieldElement[]
    for _ in 1:count
        push!(public_inputs, deserialize_field_element_binary(data[offset:offset+31]))
        offset += 32
    end
    
    return ZKProof(a, b, c, public_inputs, timestamp, proof_id)
end

# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVE SERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Serialize Point to Dict.
"""
function serialize_point_dict(point::Point)::Dict{String, String}
    return Dict{String, String}(
        "x" => string(point.x.value),
        "y" => string(point.y.value),
        "is_infinity" => string(point.is_infinity)
    )
end

"""
Deserialize Point from Dict.
"""
function deserialize_point_dict(data::Dict{String, Any})::Point
    return Point(
        FieldElement(parse(BigInt, data["x"])),
        FieldElement(parse(BigInt, data["y"])),
        parse(Bool, data["is_infinity"])
    )
end

"""
Serialize FieldElement.
"""
function serialize_field_element(fe::FieldElement)::String
    return string(fe.value)
end

"""
Deserialize FieldElement.
"""
function deserialize_field_element(s::String)::FieldElement
    return FieldElement(parse(BigInt, s))
end

"""
Serialize Point to bytes.
"""
function serialize_point_binary(point::Point)::Vector{UInt8}
    x_bytes = bigint_to_bytes(point.x.value, 32)
    y_bytes = bigint_to_bytes(point.y.value, 32)
    return vcat(x_bytes, y_bytes)
end

"""
Deserialize Point from bytes.
"""
function deserialize_point_binary(data::Vector{UInt8})::Point
    x = bytes_to_bigint(data[1:32])
    y = bytes_to_bigint(data[33:64])
    return Point(FieldElement(x), FieldElement(y))
end

"""
Serialize FieldElement to bytes.
"""
function serialize_field_element_binary(fe::FieldElement)::Vector{UInt8}
    return bigint_to_bytes(fe.value, 32)
end

"""
Deserialize FieldElement from bytes.
"""
function deserialize_field_element_binary(data::Vector{UInt8})::FieldElement
    return FieldElement(bytes_to_bigint(data))
end

"""
Serialize UUID to bytes.
"""
function serialize_uuid(id::UUID)::Vector{UInt8}
    hex = replace(string(id), "-" => "")
    return hex2bytes(hex)
end

"""
Deserialize UUID from bytes.
"""
function deserialize_uuid(data::Vector{UInt8})::UUID
    hex = bytes2hex(data)
    formatted = "$(hex[1:8])-$(hex[9:12])-$(hex[13:16])-$(hex[17:20])-$(hex[21:32])"
    return UUID(formatted)
end

"""
Serialize timestamp to bytes.
"""
function serialize_timestamp(dt::DateTime)::Vector{UInt8}
    unix_ms = Int64(Dates.value(Millisecond(dt - DateTime(1970))))
    return collect(reinterpret(UInt8, [unix_ms]))
end

"""
Deserialize timestamp from bytes.
"""
function deserialize_timestamp(data::Vector{UInt8})::DateTime
    unix_ms = reinterpret(Int64, data)[1]
    return DateTime(1970) + Millisecond(unix_ms)
end

"""
Serialize uint32 to bytes (big endian).
"""
function serialize_uint32(n::Int)::Vector{UInt8}
    return UInt8[
        (n >> 24) & 0xff,
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff
    ]
end

"""
Deserialize uint32 from bytes (big endian).
"""
function deserialize_uint32(data::Vector{UInt8})::Int
    return (Int(data[1]) << 24) |
           (Int(data[2]) << 16) |
           (Int(data[3]) << 8) |
           Int(data[4])
end

"""
Convert BigInt to bytes (big endian).
"""
function bigint_to_bytes(n::BigInt, size::Int)::Vector{UInt8}
    result = zeros(UInt8, size)
    temp = abs(n)
    
    for i in size:-1:1
        result[i] = UInt8(temp & 0xff)
        temp >>= 8
    end
    
    return result
end

"""
Convert bytes to BigInt (big endian).
"""
function bytes_to_bigint(data::Vector{UInt8})::BigInt
    result = BigInt(0)
    for b in data
        result = (result << 8) | b
    end
    return result
end

# ══════════════════════════════════════════════════════════════════════════════
# FILE I/O
# ══════════════════════════════════════════════════════════════════════════════

"""
Save proof to JSON file.
"""
function save_proof_json(proof::ZKProof, filename::String)
    data = serialize_zk_proof(proof)
    open(filename, "w") do f
        JSON3.write(f, data)
    end
end

"""
Load proof from JSON file.
"""
function load_proof_json(filename::String)::ZKProof
    data = JSON3.read(open(filename), Dict{String, Any})
    return deserialize_zk_proof(data)
end

"""
Save proof to binary file.
"""
function save_proof_binary(proof::ZKProof, filename::String)
    data = serialize_proof_binary(proof)
    write(filename, data)
end

"""
Load proof from binary file.
"""
function load_proof_binary(filename::String)::ZKProof
    data = Vector{UInt8}(read(filename))
    return deserialize_proof_binary(data)
end

"""
Save commitment to JSON file.
"""
function save_commitment_json(commitment::VulnerabilityCommitment, filename::String)
    data = serialize_commitment(commitment)
    open(filename, "w") do f
        JSON3.write(f, data)
    end
end

"""
Load commitment from JSON file.
"""
function load_commitment_json(filename::String)::VulnerabilityCommitment
    data = JSON3.read(open(filename), Dict{String, Any})
    return deserialize_commitment(data)
end

# ══════════════════════════════════════════════════════════════════════════════
# COMPRESSED SERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Compress and serialize data.
"""
function serialize_compressed(data::Vector{UInt8})::Vector{UInt8}
    # Simple RLE compression for demonstration
    # In production, use zlib or similar
    
    if isempty(data)
        return UInt8[0x00]  # Empty marker
    end
    
    result = UInt8[0x01]  # Compressed marker
    
    i = 1
    while i <= length(data)
        byte = data[i]
        count = 1
        
        while i + count <= length(data) && data[i + count] == byte && count < 255
            count += 1
        end
        
        if count >= 3
            push!(result, 0xff)  # RLE marker
            push!(result, byte)
            push!(result, UInt8(count))
        else
            for _ in 1:count
                push!(result, byte)
            end
        end
        
        i += count
    end
    
    return result
end

"""
Deserialize compressed data.
"""
function deserialize_compressed(data::Vector{UInt8})::Vector{UInt8}
    if isempty(data) || data[1] == 0x00
        return UInt8[]
    end
    
    result = UInt8[]
    i = 2  # Skip marker
    
    while i <= length(data)
        if data[i] == 0xff && i + 2 <= length(data)
            byte = data[i + 1]
            count = data[i + 2]
            append!(result, fill(byte, count))
            i += 3
        else
            push!(result, data[i])
            i += 1
        end
    end
    
    return result
end
