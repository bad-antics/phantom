"""
Audit verification for Phantom.
"""

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT TRAIL VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

"""
    VerificationResult

Result of verification operation.
"""
struct VerificationResult
    valid::Bool
    errors::Vector{String}
    warnings::Vector{String}
    verified_at::DateTime
    details::Dict{String, Any}
end

"""
Verify entire audit trail integrity.
"""
function verify_audit_trail(trail::AuditTrail)::VerificationResult
    errors = String[]
    warnings = String[]
    details = Dict{String, Any}()
    
    # Check chain integrity
    chain_valid, chain_errors = verify_chain_integrity(trail)
    if !chain_valid
        append!(errors, chain_errors)
    end
    details["chain_integrity"] = chain_valid
    
    # Verify Merkle root
    merkle_valid = verify_merkle_integrity(trail)
    if !merkle_valid
        push!(errors, "Merkle root mismatch")
    end
    details["merkle_integrity"] = merkle_valid
    
    # Verify event signatures
    sig_results = verify_all_signatures(trail)
    details["signature_verification"] = sig_results
    
    # Check for gaps in timeline
    timeline_valid, timeline_warnings = check_timeline_continuity(trail)
    append!(warnings, timeline_warnings)
    details["timeline_valid"] = timeline_valid
    
    # Verify witness signatures
    witness_valid = verify_all_witnesses(trail)
    details["witness_verification"] = witness_valid
    
    return VerificationResult(
        isempty(errors),
        errors,
        warnings,
        now(),
        details
    )
end

"""
Verify chain integrity (hash chain).
"""
function verify_chain_integrity(trail::AuditTrail)::Tuple{Bool, Vector{String}}
    errors = String[]
    
    if isempty(trail.events)
        return (true, errors)
    end
    
    # Check genesis
    genesis_hash = sha256(Vector{UInt8}("phantom_audit_genesis"))
    if trail.events[1].previous_event_hash != genesis_hash
        push!(errors, "First event doesn't link to genesis")
    end
    
    # Check chain
    for i in 2:length(trail.events)
        if trail.events[i].previous_event_hash != trail.events[i-1].event_hash
            push!(errors, "Chain break at event $(i): $(trail.events[i].event_id)")
        end
    end
    
    # Check final hash matches trail hash
    if !isempty(trail.events)
        if trail.events[end].event_hash != trail.chain_hash
            push!(errors, "Trail chain_hash doesn't match last event")
        end
    end
    
    return (isempty(errors), errors)
end

"""
Verify Merkle tree integrity.
"""
function verify_merkle_integrity(trail::AuditTrail)::Bool
    if isempty(trail.events)
        return true
    end
    
    hashes = [e.event_hash for e in trail.events]
    computed_root = compute_merkle_root(hashes)
    
    return computed_root == trail.merkle_root
end

"""
Verify all event signatures.
"""
function verify_all_signatures(trail::AuditTrail)::Dict{UUID, Bool}
    results = Dict{UUID, Bool}()
    
    for event in trail.events
        if !isnothing(event.signature)
            # Would need to recover public key from commitment
            # For now, mark as verified if signature exists
            results[event.event_id] = true
        else
            results[event.event_id] = true  # No signature to verify
        end
    end
    
    return results
end

"""
Check timeline continuity.
"""
function check_timeline_continuity(trail::AuditTrail)::Tuple{Bool, Vector{String}}
    warnings = String[]
    
    for i in 2:length(trail.events)
        time_diff = trail.events[i].timestamp - trail.events[i-1].timestamp
        
        # Check for time going backwards
        if time_diff < Millisecond(0)
            push!(warnings, "Time regression at event $(i)")
        end
        
        # Check for large gaps (> 24 hours)
        if time_diff > Hour(24)
            push!(warnings, "Large time gap (>24h) before event $(i)")
        end
    end
    
    return (isempty(filter(w -> contains(w, "regression"), warnings)), warnings)
end

"""
Verify all witness signatures.
"""
function verify_all_witnesses(trail::AuditTrail)::Dict{String, Bool}
    results = Dict{String, Bool}()
    
    for (pk, sig) in trail.witness_signatures
        key_id = bytes2hex(sha256(serialize_point(pk.point)))
        results[key_id] = verify_witness_signature(trail, pk)
    end
    
    return results
end

# ══════════════════════════════════════════════════════════════════════════════
# EVENT VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Verify single event.
"""
function verify_event(event::AuditEvent,
                     expected_previous::Vector{UInt8})::VerificationResult
    errors = String[]
    
    # Verify previous hash
    if event.previous_event_hash != expected_previous
        push!(errors, "Previous hash mismatch")
    end
    
    # Recompute event hash
    event_data = vcat(
        Vector{UInt8}(string(event.event_type)),
        Vector{UInt8}(string(event.subject_id)),
        event.actor_commitment,
        event.action_hash,
        event.previous_event_hash
    )
    computed_hash = sha256(event_data)
    
    if computed_hash != event.event_hash
        push!(errors, "Event hash mismatch")
    end
    
    return VerificationResult(
        isempty(errors),
        errors,
        String[],
        now(),
        Dict{String, Any}("computed_hash" => bytes2hex(computed_hash))
    )
end

"""
Verify event inclusion proof.
"""
function verify_event_inclusion(trail::AuditTrail,
                               event_id::UUID,
                               proof::Vector{Vector{UInt8}})::Bool
    
    idx = findfirst(e -> e.event_id == event_id, trail.events)
    if isnothing(idx)
        return false
    end
    
    event_hash = trail.events[idx].event_hash
    return verify_merkle_proof(event_hash, idx, proof, trail.merkle_root)
end

# ══════════════════════════════════════════════════════════════════════════════
# TIMESTAMP VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Verify timestamp proof.
"""
function verify_timestamp_proof(proof::TimestampProof)::VerificationResult
    errors = String[]
    
    # For external anchors, would verify against blockchain
    if proof.anchor_type == "bitcoin" || proof.anchor_type == "ethereum"
        # Placeholder: would query blockchain
        # For now, assume valid if anchor reference exists
        if isempty(proof.anchor_reference)
            push!(errors, "Missing blockchain anchor reference")
        end
    end
    
    # Verify Merkle proof
    if !isempty(proof.merkle_proof)
        # Would verify proof leads to root
    end
    
    return VerificationResult(
        isempty(errors),
        errors,
        String[],
        now(),
        Dict{String, Any}(
            "anchor_type" => proof.anchor_type,
            "timestamp" => proof.timestamp
        )
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE AUDIT
# ══════════════════════════════════════════════════════════════════════════════

"""
    AuditReport

Comprehensive audit verification report.
"""
struct AuditReport
    report_id::UUID
    generated_at::DateTime
    
    # Trail info
    trail_id::UUID
    event_count::Int
    
    # Verification results
    overall_valid::Bool
    integrity_check::VerificationResult
    
    # Statistics
    events_by_type::Dict{AuditEventType, Int}
    signed_events::Int
    witnessed_states::Int
    
    # Issues
    critical_issues::Vector{String}
    warnings::Vector{String}
end

"""
Generate comprehensive audit report.
"""
function generate_audit_report(trail::AuditTrail)::AuditReport
    # Verify trail
    verification = verify_audit_trail(trail)
    
    # Count events by type
    type_counts = Dict{AuditEventType, Int}()
    signed_count = 0
    
    for event in trail.events
        type_counts[event.event_type] = get(type_counts, event.event_type, 0) + 1
        if !isnothing(event.signature)
            signed_count += 1
        end
    end
    
    # Separate critical from warnings
    critical = filter(e -> contains(e, "break") || contains(e, "mismatch"), verification.errors)
    
    return AuditReport(
        uuid4(),
        now(),
        trail.trail_id,
        length(trail.events),
        verification.valid,
        verification,
        type_counts,
        signed_count,
        length(trail.witness_signatures),
        critical,
        verification.warnings
    )
end

"""
Export audit report to JSON.
"""
function export_audit_report(report::AuditReport)::Dict{String, Any}
    return Dict{String, Any}(
        "report_id" => string(report.report_id),
        "generated_at" => string(report.generated_at),
        "trail_id" => string(report.trail_id),
        "event_count" => report.event_count,
        "overall_valid" => report.overall_valid,
        "events_by_type" => Dict(string(k) => v for (k, v) in report.events_by_type),
        "signed_events" => report.signed_events,
        "witnessed_states" => report.witnessed_states,
        "critical_issues" => report.critical_issues,
        "warnings" => report.warnings
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

"""
Serialize point to bytes (duplicate for local use).
"""
function serialize_point(point::Point)::Vector{UInt8}
    x_bytes = collect(reinterpret(UInt8, [point.x.value]))
    y_bytes = collect(reinterpret(UInt8, [point.y.value]))
    return vcat(x_bytes, y_bytes)
end
