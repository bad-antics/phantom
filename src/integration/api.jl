"""
External API integration for Phantom.
"""

# ══════════════════════════════════════════════════════════════════════════════
# API CLIENT
# ══════════════════════════════════════════════════════════════════════════════

"""
    PhantomAPIConfig

Configuration for Phantom API endpoints.
"""
struct PhantomAPIConfig
    base_url::String
    api_version::String
    timeout::Int  # seconds
    verify_ssl::Bool
    
    # Authentication
    auth_method::Symbol  # :none, :api_key, :jwt, :signature
    api_key::Union{String, Nothing}
    signing_key::Union{SchnorrPrivateKey, Nothing}
end

"""
Create default API config.
"""
function default_api_config()::PhantomAPIConfig
    return PhantomAPIConfig(
        "https://api.phantom.security",
        "v1",
        30,
        true,
        :none,
        nothing,
        nothing
    )
end

"""
    APIResponse

Response from API call.
"""
struct APIResponse
    success::Bool
    status_code::Int
    data::Dict{String, Any}
    error::Union{String, Nothing}
    request_id::String
    timestamp::DateTime
end

# ══════════════════════════════════════════════════════════════════════════════
# PROOF SUBMISSION API
# ══════════════════════════════════════════════════════════════════════════════

"""
Submit proof to verification service.
"""
function submit_proof(config::PhantomAPIConfig,
                     proof::VulnerabilityProof)::APIResponse
    
    # Serialize proof
    proof_data = Dict{String, Any}(
        "proof_id" => string(proof.zk_proof.proof_id),
        "commitment" => bytes2hex(proof.commitment.severity_commitment),
        "claims" => Dict(k => v for (k, v) in proof.claims),
        "timestamp" => string(proof.zk_proof.timestamp),
        "proof" => Dict{String, Any}(
            "a" => serialize_point_hex(proof.zk_proof.a),
            "b" => serialize_point_hex(proof.zk_proof.b),
            "c" => serialize_point_hex(proof.zk_proof.c)
        )
    )
    
    return api_request(config, "POST", "/proofs/submit", proof_data)
end

"""
Request proof verification.
"""
function verify_proof_remote(config::PhantomAPIConfig,
                            proof_id::UUID)::APIResponse
    
    return api_request(config, "GET", "/proofs/$(proof_id)/verify", Dict{String, Any}())
end

"""
Get proof status.
"""
function get_proof_status(config::PhantomAPIConfig,
                         proof_id::UUID)::APIResponse
    
    return api_request(config, "GET", "/proofs/$(proof_id)/status", Dict{String, Any}())
end

# ══════════════════════════════════════════════════════════════════════════════
# DISCLOSURE API
# ══════════════════════════════════════════════════════════════════════════════

"""
Register disclosure with coordinator.
"""
function register_disclosure(config::PhantomAPIConfig,
                            disclosure::StagedDisclosure)::APIResponse
    
    disclosure_data = Dict{String, Any}(
        "disclosure_id" => string(disclosure.disclosure_id),
        "policy" => Dict{String, Any}(
            "name" => disclosure.policy.name,
            "vendor_notify_delay" => string(disclosure.policy.vendor_notify_delay),
            "partial_disclosure_delay" => string(disclosure.policy.partial_disclosure_delay),
            "full_disclosure_delay" => string(disclosure.policy.full_disclosure_delay)
        ),
        "current_stage" => string(disclosure.current_stage),
        "started_at" => string(disclosure.started_at)
    )
    
    return api_request(config, "POST", "/disclosures/register", disclosure_data)
end

"""
Advance disclosure stage.
"""
function advance_disclosure_stage(config::PhantomAPIConfig,
                                 disclosure_id::UUID,
                                 new_stage::DisclosureStage,
                                 reveal_data::Vector{UInt8})::APIResponse
    
    data = Dict{String, Any}(
        "disclosure_id" => string(disclosure_id),
        "new_stage" => string(new_stage),
        "reveal" => bytes2hex(reveal_data)
    )
    
    return api_request(config, "POST", "/disclosures/advance", data)
end

# ══════════════════════════════════════════════════════════════════════════════
# REPORT SUBMISSION API
# ══════════════════════════════════════════════════════════════════════════════

"""
Submit anonymous report to coordinator.
"""
function submit_anonymous_report(config::PhantomAPIConfig,
                                report::AnonymousReport)::APIResponse
    
    report_data = Dict{String, Any}(
        "report_id" => string(report.report_id),
        "commitment" => Dict{String, Any}(
            "severity" => bytes2hex(report.commitment.severity_commitment),
            "type" => bytes2hex(report.commitment.type_commitment),
            "description" => bytes2hex(report.commitment.description_commitment)
        ),
        "channel" => report.submission_channel,
        "created_at" => string(report.created_at)
    )
    
    # Add ring signature if present
    if !isnothing(report.ring_signature)
        report_data["ring_signature"] = Dict{String, Any}(
            "key_image" => serialize_point_hex(report.ring_signature.key_image),
            "ring_size" => length(report.ring_signature.responses)
        )
    end
    
    return api_request(config, "POST", "/reports/submit", report_data)
end

"""
Get report verification status.
"""
function get_report_status(config::PhantomAPIConfig,
                          report_id::UUID)::APIResponse
    
    return api_request(config, "GET", "/reports/$(report_id)/status", Dict{String, Any}())
end

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT API
# ══════════════════════════════════════════════════════════════════════════════

"""
Submit audit trail for external witnessing.
"""
function submit_audit_trail(config::PhantomAPIConfig,
                           trail::AuditTrail)::APIResponse
    
    trail_data = export_audit_trail(trail)
    
    return api_request(config, "POST", "/audit/trails/submit", trail_data)
end

"""
Request witness signature for audit trail.
"""
function request_witness_signature(config::PhantomAPIConfig,
                                  trail_id::UUID)::APIResponse
    
    return api_request(config, "POST", "/audit/trails/$(trail_id)/witness", Dict{String, Any}())
end

"""
Verify audit trail with external service.
"""
function verify_audit_trail_remote(config::PhantomAPIConfig,
                                  trail_id::UUID)::APIResponse
    
    return api_request(config, "GET", "/audit/trails/$(trail_id)/verify", Dict{String, Any}())
end

# ══════════════════════════════════════════════════════════════════════════════
# BOUNTY API
# ══════════════════════════════════════════════════════════════════════════════

"""
Submit reward claim.
"""
function submit_reward_claim(config::PhantomAPIConfig,
                            claim::RewardClaim)::APIResponse
    
    claim_data = Dict{String, Any}(
        "report_id" => string(claim.report_id),
        "payment_commitment" => bytes2hex(claim.payment_commitment),
        "amount_range" => claim.amount_range
    )
    
    return api_request(config, "POST", "/bounty/claims/submit", claim_data)
end

"""
Get claim status.
"""
function get_claim_status(config::PhantomAPIConfig,
                         claim_id::UUID)::APIResponse
    
    return api_request(config, "GET", "/bounty/claims/$(claim_id)/status", Dict{String, Any}())
end

# ══════════════════════════════════════════════════════════════════════════════
# API REQUEST HELPERS
# ══════════════════════════════════════════════════════════════════════════════

"""
Make API request.
"""
function api_request(config::PhantomAPIConfig,
                    method::String,
                    endpoint::String,
                    data::Dict{String, Any})::APIResponse
    
    url = "$(config.base_url)/$(config.api_version)$(endpoint)"
    request_id = string(uuid4())
    
    headers = Dict{String, String}(
        "Content-Type" => "application/json",
        "X-Request-ID" => request_id,
        "X-API-Version" => config.api_version
    )
    
    # Add authentication
    if config.auth_method == :api_key && !isnothing(config.api_key)
        headers["Authorization"] = "Bearer $(config.api_key)"
    elseif config.auth_method == :signature && !isnothing(config.signing_key)
        # Sign request
        timestamp = string(now())
        sign_data = vcat(
            Vector{UInt8}(method),
            Vector{UInt8}(endpoint),
            Vector{UInt8}(timestamp)
        )
        sig = schnorr_sign(config.signing_key, sign_data)
        headers["X-Signature"] = serialize_signature_hex(sig)
        headers["X-Timestamp"] = timestamp
    end
    
    try
        # Make HTTP request
        body = JSON3.write(data)
        
        response = if method == "GET"
            HTTP.get(url, headers; status_exception=false, readtimeout=config.timeout)
        elseif method == "POST"
            HTTP.post(url, headers, body; status_exception=false, readtimeout=config.timeout)
        elseif method == "PUT"
            HTTP.put(url, headers, body; status_exception=false, readtimeout=config.timeout)
        elseif method == "DELETE"
            HTTP.delete(url, headers; status_exception=false, readtimeout=config.timeout)
        else
            throw(ArgumentError("Unsupported HTTP method: $method"))
        end
        
        response_data = try
            JSON3.read(String(response.body), Dict{String, Any})
        catch
            Dict{String, Any}("raw" => String(response.body))
        end
        
        return APIResponse(
            200 <= response.status < 300,
            response.status,
            response_data,
            response.status >= 400 ? get(response_data, "error", "Unknown error") : nothing,
            request_id,
            now()
        )
        
    catch e
        return APIResponse(
            false,
            0,
            Dict{String, Any}(),
            string(e),
            request_id,
            now()
        )
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# SERIALIZATION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

"""
Serialize point to hex.
"""
function serialize_point_hex(point::Point)::String
    bytes = serialize_point(point)
    return bytes2hex(bytes)
end

"""
Serialize signature to hex.
"""
function serialize_signature_hex(sig::SchnorrSignature)::String
    r_bytes = serialize_point(sig.r)
    s_bytes = collect(reinterpret(UInt8, [sig.s.value]))
    return bytes2hex(vcat(r_bytes, s_bytes))
end

"""
Serialize point to bytes.
"""
function serialize_point(point::Point)::Vector{UInt8}
    x_bytes = collect(reinterpret(UInt8, [point.x.value]))
    y_bytes = collect(reinterpret(UInt8, [point.y.value]))
    return vcat(x_bytes, y_bytes)
end

"""
Convert bytes to hex.
"""
function bytes2hex(data::Vector{UInt8})::String
    return join([string(b, base=16, pad=2) for b in data])
end
