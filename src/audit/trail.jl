"""
Cryptographic audit trails for Phantom.
"""

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT TRAIL
# ══════════════════════════════════════════════════════════════════════════════

"""
    AuditEventType

Types of auditable events.
"""
@enum AuditEventType begin
    AUDIT_COMMITMENT_CREATED
    AUDIT_PROOF_GENERATED
    AUDIT_PROOF_VERIFIED
    AUDIT_DISCLOSURE_STARTED
    AUDIT_STAGE_ADVANCED
    AUDIT_REVEAL_COMPLETED
    AUDIT_REPORT_SUBMITTED
    AUDIT_CLAIM_FILED
    AUDIT_SIGNATURE_VERIFIED
    AUDIT_POLICY_UPDATED
end

"""
    AuditEvent

Single auditable event with cryptographic binding.
"""
struct AuditEvent
    event_id::UUID
    event_type::AuditEventType
    timestamp::DateTime
    
    # Event data
    subject_id::UUID           # What this event is about
    actor_commitment::Vector{UInt8}  # Commitment to actor (may be anonymous)
    action_hash::Vector{UInt8}       # Hash of action details
    
    # Cryptographic binding
    previous_event_hash::Vector{UInt8}
    event_hash::Vector{UInt8}
    
    # Proofs
    inclusion_proof::Union{Vector{Vector{UInt8}}, Nothing}
    signature::Union{SchnorrSignature, Nothing}
    
    # Metadata
    metadata::Dict{String, Any}
end

"""
    AuditTrail

Append-only cryptographic audit trail.
"""
mutable struct AuditTrail
    trail_id::UUID
    created_at::DateTime
    
    # Events
    events::Vector{AuditEvent}
    
    # Merkle tree for events
    merkle_root::Vector{UInt8}
    
    # Trail integrity
    chain_hash::Vector{UInt8}
    
    # Witnesses
    witness_signatures::Vector{Tuple{SchnorrPublicKey, SchnorrSignature}}
end

"""
Create new audit trail.
"""
function create_audit_trail()::AuditTrail
    genesis_hash = sha256(Vector{UInt8}("phantom_audit_genesis"))
    
    return AuditTrail(
        uuid4(),
        now(),
        AuditEvent[],
        genesis_hash,
        genesis_hash,
        Tuple{SchnorrPublicKey, SchnorrSignature}[]
    )
end

"""
Add event to audit trail.
"""
function add_audit_event!(trail::AuditTrail,
                         event_type::AuditEventType,
                         subject_id::UUID,
                         action_details::Dict{String, Any};
                         actor_key::Union{SchnorrPrivateKey, Nothing}=nothing)::AuditEvent
    
    # Create action hash
    action_str = join([string(k, "=", v) for (k, v) in action_details], ";")
    action_hash = sha256(Vector{UInt8}(action_str))
    
    # Create actor commitment (anonymous if no key provided)
    actor_commitment = if !isnothing(actor_key)
        sha256(serialize_point(actor_key.public_key.point))
    else
        sha256(rand(UInt8, 32))  # Random commitment for anonymous actor
    end
    
    # Get previous hash
    previous_hash = isempty(trail.events) ? trail.chain_hash : trail.events[end].event_hash
    
    # Compute event hash
    event_data = vcat(
        Vector{UInt8}(string(event_type)),
        Vector{UInt8}(string(subject_id)),
        actor_commitment,
        action_hash,
        previous_hash
    )
    event_hash = sha256(event_data)
    
    # Create signature if actor key provided
    signature = if !isnothing(actor_key)
        schnorr_sign(actor_key, event_hash)
    else
        nothing
    end
    
    # Create event
    event = AuditEvent(
        uuid4(),
        event_type,
        now(),
        subject_id,
        actor_commitment,
        action_hash,
        previous_hash,
        event_hash,
        nothing,
        signature,
        Dict{String, Any}()
    )
    
    push!(trail.events, event)
    
    # Update chain hash
    trail.chain_hash = event_hash
    
    # Update Merkle root
    update_merkle_root!(trail)
    
    return event
end

"""
Update Merkle root of audit trail.
"""
function update_merkle_root!(trail::AuditTrail)
    if isempty(trail.events)
        return
    end
    
    hashes = [e.event_hash for e in trail.events]
    trail.merkle_root = compute_merkle_root(hashes)
end

"""
Get inclusion proof for event.
"""
function get_event_inclusion_proof(trail::AuditTrail,
                                  event_id::UUID)::Union{Vector{Vector{UInt8}}, Nothing}
    
    idx = findfirst(e -> e.event_id == event_id, trail.events)
    if isnothing(idx)
        return nothing
    end
    
    hashes = [e.event_hash for e in trail.events]
    return generate_merkle_proof(hashes, idx)
end

# ══════════════════════════════════════════════════════════════════════════════
# WITNESS SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

"""
    Witness

Third-party that attests to audit trail state.
"""
struct Witness
    witness_id::UUID
    public_key::SchnorrPublicKey
    name::String
    established_at::DateTime
end

"""
Add witness signature to trail.
"""
function add_witness_signature!(trail::AuditTrail,
                               witness_key::SchnorrPrivateKey)::Bool
    
    # Sign current state
    state_data = vcat(
        Vector{UInt8}(string(trail.trail_id)),
        trail.merkle_root,
        trail.chain_hash,
        Vector{UInt8}(string(length(trail.events)))
    )
    
    signature = schnorr_sign(witness_key, state_data)
    
    push!(trail.witness_signatures, (witness_key.public_key, signature))
    
    return true
end

"""
Verify witness signature.
"""
function verify_witness_signature(trail::AuditTrail,
                                 witness_public_key::SchnorrPublicKey)::Bool
    
    # Find matching signature
    for (pk, sig) in trail.witness_signatures
        if pk.point.x == witness_public_key.point.x && 
           pk.point.y == witness_public_key.point.y
            
            state_data = vcat(
                Vector{UInt8}(string(trail.trail_id)),
                trail.merkle_root,
                trail.chain_hash,
                Vector{UInt8}(string(length(trail.events)))
            )
            
            return schnorr_verify(pk, state_data, sig)
        end
    end
    
    return false
end

# ══════════════════════════════════════════════════════════════════════════════
# TIMESTAMPING
# ══════════════════════════════════════════════════════════════════════════════

"""
    TimestampProof

Proof of existence at a specific time.
"""
struct TimestampProof
    timestamp::DateTime
    data_hash::Vector{UInt8}
    
    # Merkle proof in timestamp tree
    merkle_proof::Vector{Vector{UInt8}}
    merkle_root::Vector{UInt8}
    
    # External anchor (e.g., blockchain tx)
    anchor_type::String  # "bitcoin", "ethereum", "internal"
    anchor_reference::String
end

"""
Create timestamp proof for event.
"""
function create_timestamp_proof(event::AuditEvent,
                               anchor_type::String="internal")::TimestampProof
    
    # For internal anchoring, just use current time
    # For external, would submit to blockchain
    
    merkle_proof = Vector{UInt8}[]  # Placeholder
    merkle_root = sha256(event.event_hash)
    
    anchor_reference = if anchor_type == "internal"
        string(uuid4())
    else
        "pending_blockchain_tx"
    end
    
    return TimestampProof(
        now(),
        event.event_hash,
        merkle_proof,
        merkle_root,
        anchor_type,
        anchor_reference
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT QUERIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Query events by type.
"""
function query_events_by_type(trail::AuditTrail,
                             event_type::AuditEventType)::Vector{AuditEvent}
    return filter(e -> e.event_type == event_type, trail.events)
end

"""
Query events by subject.
"""
function query_events_by_subject(trail::AuditTrail,
                                subject_id::UUID)::Vector{AuditEvent}
    return filter(e -> e.subject_id == subject_id, trail.events)
end

"""
Query events in time range.
"""
function query_events_by_time(trail::AuditTrail,
                             start_time::DateTime,
                             end_time::DateTime)::Vector{AuditEvent}
    return filter(e -> start_time <= e.timestamp <= end_time, trail.events)
end

"""
Get audit trail summary.
"""
function audit_trail_summary(trail::AuditTrail)::Dict{String, Any}
    event_counts = Dict{AuditEventType, Int}()
    for event in trail.events
        event_counts[event.event_type] = get(event_counts, event.event_type, 0) + 1
    end
    
    return Dict{String, Any}(
        "trail_id" => trail.trail_id,
        "created_at" => trail.created_at,
        "total_events" => length(trail.events),
        "event_counts" => event_counts,
        "merkle_root" => bytes2hex(trail.merkle_root),
        "chain_hash" => bytes2hex(trail.chain_hash),
        "witness_count" => length(trail.witness_signatures)
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# EXPORT FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

"""
Export audit trail to JSON.
"""
function export_audit_trail(trail::AuditTrail)::Dict{String, Any}
    events_data = [Dict{String, Any}(
        "event_id" => e.event_id,
        "event_type" => string(e.event_type),
        "timestamp" => e.timestamp,
        "subject_id" => e.subject_id,
        "actor_commitment" => bytes2hex(e.actor_commitment),
        "action_hash" => bytes2hex(e.action_hash),
        "previous_event_hash" => bytes2hex(e.previous_event_hash),
        "event_hash" => bytes2hex(e.event_hash)
    ) for e in trail.events]
    
    return Dict{String, Any}(
        "trail_id" => trail.trail_id,
        "created_at" => trail.created_at,
        "events" => events_data,
        "merkle_root" => bytes2hex(trail.merkle_root),
        "chain_hash" => bytes2hex(trail.chain_hash),
        "witness_count" => length(trail.witness_signatures)
    )
end

"""
Convert bytes to hex string.
"""
function bytes2hex(data::Vector{UInt8})::String
    return join([string(b, base=16, pad=2) for b in data])
end
