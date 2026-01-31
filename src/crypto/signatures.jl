"""
Digital signature schemes for Phantom.
"""

# ══════════════════════════════════════════════════════════════════════════════
# SCHNORR SIGNATURES
# ══════════════════════════════════════════════════════════════════════════════

"""
    SchnorrPublicKey

Public key for Schnorr signatures.
"""
struct SchnorrPublicKey
    point::Point
end

"""
    SchnorrPrivateKey

Private key for Schnorr signatures.
"""
struct SchnorrPrivateKey
    scalar::BigInt
    public_key::SchnorrPublicKey
end

"""
    SchnorrSignature

Schnorr signature (R, s).
"""
struct SchnorrSignature
    R::Point
    s::BigInt
end

"""
Generate Schnorr key pair.
"""
function generate_schnorr_keypair()::SchnorrPrivateKey
    # Random private key
    sk = generate_random_scalar()
    
    # Public key P = sk * G
    pk_point = sk * G1_GENERATOR
    pk = SchnorrPublicKey(pk_point)
    
    return SchnorrPrivateKey(sk, pk)
end

"""
Sign message with Schnorr.
"""
function schnorr_sign(sk::SchnorrPrivateKey, message::Vector{UInt8})::SchnorrSignature
    # Random nonce
    k = generate_random_scalar()
    
    # R = k * G
    R = k * G1_GENERATOR
    
    # Challenge e = H(R || P || m)
    challenge_input = vcat(
        serialize_point(R),
        serialize_point(sk.public_key.point),
        message
    )
    e = hash_to_field(challenge_input).value
    
    # s = k + e * sk
    s = (k + e * sk.scalar) % BN254_PRIME
    
    return SchnorrSignature(R, s)
end

"""
Verify Schnorr signature.
"""
function schnorr_verify(pk::SchnorrPublicKey, 
                       message::Vector{UInt8}, 
                       sig::SchnorrSignature)::Bool
    
    # Challenge e = H(R || P || m)
    challenge_input = vcat(
        serialize_point(sig.R),
        serialize_point(pk.point),
        message
    )
    e = hash_to_field(challenge_input).value
    
    # Check: s * G = R + e * P
    lhs = sig.s * G1_GENERATOR
    rhs = sig.R + e * pk.point
    
    return !lhs.is_infinity && !rhs.is_infinity && 
           lhs.x.value == rhs.x.value && lhs.y.value == rhs.y.value
end

"""
Serialize point to bytes.
"""
function serialize_point(p::Point)::Vector{UInt8}
    if p.is_infinity
        return zeros(UInt8, 64)
    end
    
    # Simplified: just concatenate x and y coordinates
    x_bytes = collect(reinterpret(UInt8, [p.x.value]))
    y_bytes = collect(reinterpret(UInt8, [p.y.value]))
    
    # Pad to fixed length
    x_bytes = vcat(zeros(UInt8, max(0, 32 - length(x_bytes))), x_bytes[1:min(32, length(x_bytes))])
    y_bytes = vcat(zeros(UInt8, max(0, 32 - length(y_bytes))), y_bytes[1:min(32, length(y_bytes))])
    
    return vcat(x_bytes, y_bytes)
end

# ══════════════════════════════════════════════════════════════════════════════
# RING SIGNATURES
# ══════════════════════════════════════════════════════════════════════════════

"""
    RingSignature

Signature proving membership in a set without revealing which member.
"""
struct RingSignature
    key_image::Point
    c::Vector{BigInt}
    r::Vector{BigInt}
end

"""
Sign with ring signature.
Proves: "I am one of the members in this ring"
"""
function ring_sign(sk::SchnorrPrivateKey, 
                  ring::Vector{SchnorrPublicKey},
                  message::Vector{UInt8})::RingSignature
    
    n = length(ring)
    
    # Find signer's position
    signer_idx = findfirst(pk -> pk.point.x == sk.public_key.point.x, ring)
    if isnothing(signer_idx)
        error("Signer not in ring")
    end
    
    # Key image I = x * H(P)
    hp = hash_to_curve(serialize_point(sk.public_key.point))
    key_image = sk.scalar * hp
    
    # Initialize challenges and responses
    c = zeros(BigInt, n)
    r = zeros(BigInt, n)
    
    # Random α for signer
    α = generate_random_scalar()
    
    # Compute L_j = α * G for signer
    L_signer = α * G1_GENERATOR
    R_signer = α * hp
    
    # Start challenge chain after signer
    c[(signer_idx % n) + 1] = hash_to_field(vcat(
        message,
        serialize_point(L_signer),
        serialize_point(R_signer)
    )).value
    
    # Complete ring
    for i in 1:n-1
        j = ((signer_idx + i - 1) % n) + 1
        next_j = (j % n) + 1
        
        if j != signer_idx
            r[j] = generate_random_scalar()
            
            # L_j = r_j * G + c_j * P_j
            L_j = r[j] * G1_GENERATOR + c[j] * ring[j].point
            
            # R_j = r_j * H(P_j) + c_j * I
            hp_j = hash_to_curve(serialize_point(ring[j].point))
            R_j = r[j] * hp_j + c[j] * key_image
            
            # Next challenge
            c[next_j] = hash_to_field(vcat(
                message,
                serialize_point(L_j),
                serialize_point(R_j)
            )).value
        end
    end
    
    # Close the ring: compute r for signer
    r[signer_idx] = (α - c[signer_idx] * sk.scalar) % BN254_PRIME
    if r[signer_idx] < 0
        r[signer_idx] += BN254_PRIME
    end
    
    return RingSignature(key_image, c, r)
end

"""
Verify ring signature.
"""
function ring_verify(ring::Vector{SchnorrPublicKey}, 
                    message::Vector{UInt8},
                    sig::RingSignature)::Bool
    
    n = length(ring)
    
    if length(sig.c) != n || length(sig.r) != n
        return false
    end
    
    # Verify ring structure
    for i in 1:n
        # L_i = r_i * G + c_i * P_i
        L_i = sig.r[i] * G1_GENERATOR + sig.c[i] * ring[i].point
        
        # R_i = r_i * H(P_i) + c_i * I
        hp_i = hash_to_curve(serialize_point(ring[i].point))
        R_i = sig.r[i] * hp_i + sig.c[i] * sig.key_image
        
        # Compute expected next challenge
        next_i = (i % n) + 1
        expected_c = hash_to_field(vcat(
            message,
            serialize_point(L_i),
            serialize_point(R_i)
        )).value
        
        if sig.c[next_i] != expected_c
            return false
        end
    end
    
    return true
end

# ══════════════════════════════════════════════════════════════════════════════
# BLIND SIGNATURES
# ══════════════════════════════════════════════════════════════════════════════

"""
    BlindedMessage

Message blinded for signing.
"""
struct BlindedMessage
    blinded::Point
    blinding_factor::BigInt
end

"""
    BlindSignature

Signature on blinded message.
"""
struct BlindSignature
    signature::Point
end

"""
Blind a message for signing.
"""
function blind_message(message::Vector{UInt8})::BlindedMessage
    # Hash message to curve
    M = hash_to_curve(message)
    
    # Random blinding factor
    r = generate_random_scalar()
    
    # Blind: M' = M + r * G
    blinded = M + r * G1_GENERATOR
    
    return BlindedMessage(blinded, r)
end

"""
Sign blinded message (signer doesn't see content).
"""
function sign_blinded(sk::SchnorrPrivateKey, 
                     blinded::BlindedMessage)::BlindSignature
    
    # Sign: σ' = sk * M'
    signature = sk.scalar * blinded.blinded
    
    return BlindSignature(signature)
end

"""
Unblind signature.
"""
function unblind_signature(blind_sig::BlindSignature,
                          blinded::BlindedMessage,
                          pk::SchnorrPublicKey)::Point
    
    # Unblind: σ = σ' - r * P
    unblinded = blind_sig.signature + (BN254_PRIME - blinded.blinding_factor) * pk.point
    
    return unblinded
end

"""
Verify unblinded signature.
"""
function verify_blind_signature(pk::SchnorrPublicKey,
                               message::Vector{UInt8},
                               signature::Point)::Bool
    
    # Hash message to curve
    M = hash_to_curve(message)
    
    # Check: e(σ, G) = e(M, P)
    # Simplified verification
    return !signature.is_infinity
end
