"""
    Phantom

Zero-Knowledge Proof Security Framework for Julia.
Prove vulnerabilities exist without revealing sensitive details.

## Features
- ZK-SNARK proofs for vulnerability claims
- Commitment schemes for responsible disclosure
- Anonymous vulnerability reporting
- Cryptographic audit trails
- Privacy-preserving security assessments

## Quick Start
```julia
using Phantom

# Create vulnerability details
details = VulnerabilityDetails(
    title = "SQL Injection in Login",
    description = "Authentication bypass via malicious input",
    affected_systems = ["api.example.com"],
    severity = VULN_CRITICAL,
    vuln_type = TYPE_INJECTION,
    proof_of_concept = "' OR '1'='1",
    steps_to_reproduce = ["Navigate to login", "Enter payload"]
)

# Create commitment (hides details)
commitment = create_vulnerability_commitment(details)

# Generate ZK proof
proof = generate_vulnerability_proof(commitment, details)

# Verify without seeing details
is_valid = verify_vulnerability_proof(proof, commitment)
```
"""
module Phantom

using Dates
using JSON3
using HTTP
using SHA
using Random
using LinearAlgebra
using Serialization
using UUIDs
using Logging
using Printf

# ══════════════════════════════════════════════════════════════════════════════
# VERSION
# ══════════════════════════════════════════════════════════════════════════════

const PHANTOM_VERSION = v"0.1.0"

# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS
# ══════════════════════════════════════════════════════════════════════════════

export
    # Version
    PHANTOM_VERSION,
    
    # Cryptographic primitives
    FieldElement, Point, BN254_PRIME, G1_GENERATOR,
    hash_to_field, hash_to_curve,
    compute_merkle_root, generate_merkle_proof, verify_merkle_proof,
    
    # Commitment schemes
    PedersenCommitment, PedersenParameters, HashCommitment,
    VectorCommitment, TimeLockPuzzle,
    generate_pedersen_params, pedersen_commit, verify_pedersen,
    hash_commit, verify_hash_commit,
    create_vector_commitment,
    
    # ZK-SNARK
    ArithmeticCircuit, Gate, Wire, ProvingKey, VerificationKey, ZKProof,
    setup, generate_proof, verify_proof,
    build_vulnerability_circuit, build_severity_circuit,
    
    # Signatures
    SchnorrPublicKey, SchnorrPrivateKey, SchnorrSignature,
    generate_schnorr_keypair, schnorr_sign, schnorr_verify,
    RingSignature, ring_sign, ring_verify,
    BlindedMessage, BlindSignature, blind_message, blind_sign, unblind_signature,
    
    # Vulnerability types
    VulnerabilitySeverity, VulnerabilityType,
    VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM, VULN_LOW, VULN_INFO,
    TYPE_INJECTION, TYPE_BUFFER_OVERFLOW, TYPE_XSS, TYPE_AUTH_BYPASS,
    TYPE_CRYPTO_WEAKNESS, TYPE_INFO_DISCLOSURE, TYPE_RCE, TYPE_PRIVILEGE_ESCALATION,
    TYPE_DOS, TYPE_LOGIC_FLAW,
    VulnerabilityCommitment, VulnerabilityMetadata, VulnerabilityDetails,
    create_vulnerability_commitment, create_vulnerability_record,
    
    # Proof generation
    VulnerabilityProof, SeverityProof, TimelineProof, ExploitabilityProof,
    CompositeProof,
    generate_vulnerability_proof, verify_vulnerability_proof,
    generate_severity_proof, verify_severity_proof,
    generate_timeline_proof, generate_exploitability_proof,
    create_composite_proof, verify_composite_proof,
    
    # Disclosure
    DisclosureStage, DisclosurePolicy, TimeLockDisclosure, StagedDisclosure,
    STAGE_COMMITTED, STAGE_VENDOR_NOTIFIED, STAGE_PARTIAL_DISCLOSURE, STAGE_FULL_DISCLOSURE,
    standard_disclosure_policy, rapid_disclosure_policy, extended_disclosure_policy,
    create_time_lock_disclosure, create_staged_disclosure,
    advance_disclosure!, can_advance_stage, get_current_reveal,
    
    # Anonymous reporting
    AnonymousReport, Pseudonym, RewardClaim, ProtectedDisclosure,
    create_anonymous_report, verify_anonymous_report,
    derive_pseudonym, prove_same_identity,
    create_reward_claim, verify_reward_claim,
    create_protected_disclosure, send_heartbeat!, check_dead_mans_switch,
    
    # Mixing
    MixerPool, OnionPacket, CoinJoinSession, TimingProtection,
    create_mixer_pool, add_to_pool!, mix_and_release!,
    create_onion_report, peel_onion_layer,
    create_coinjoin_session, join_coinjoin!, complete_coinjoin!,
    
    # Audit trail
    AuditEventType, AuditEvent, AuditTrail, TimestampProof, Witness,
    AUDIT_COMMITMENT_CREATED, AUDIT_PROOF_GENERATED, AUDIT_PROOF_VERIFIED,
    AUDIT_DISCLOSURE_STARTED, AUDIT_STAGE_ADVANCED, AUDIT_REVEAL_COMPLETED,
    create_audit_trail, add_audit_event!, get_event_inclusion_proof,
    add_witness_signature!, verify_witness_signature,
    create_timestamp_proof,
    query_events_by_type, query_events_by_subject, query_events_by_time,
    audit_trail_summary, export_audit_trail,
    
    # Audit verification
    VerificationResult, AuditReport,
    verify_audit_trail, verify_event, verify_event_inclusion,
    verify_timestamp_proof, generate_audit_report, export_audit_report,
    
    # API integration
    PhantomAPIConfig, APIResponse,
    default_api_config,
    submit_proof, verify_proof_remote, get_proof_status,
    register_disclosure, advance_disclosure_stage,
    submit_anonymous_report, get_report_status,
    submit_audit_trail, request_witness_signature, verify_audit_trail_remote,
    submit_reward_claim, get_claim_status,
    
    # Blockchain
    BlockchainType, BlockchainConfig, BlockchainAnchor,
    AnchorRequest, MerkleAnchorBatch, AnchorProof,
    BLOCKCHAIN_BITCOIN, BLOCKCHAIN_ETHEREUM, BLOCKCHAIN_POLYGON,
    bitcoin_config, ethereum_config,
    anchor_to_bitcoin, anchor_to_ethereum,
    verify_bitcoin_anchor, verify_ethereum_anchor,
    create_anchor_batch, add_to_batch!, finalize_batch!, anchor_batch!,
    create_anchor_proof, verify_anchor_proof,
    
    # Utilities
    sha256, sha256d, hmac_sha256,
    bytes2hex, hex2bytes, base64_encode, base64_decode,
    secure_random, generate_nonce, random_scalar,
    unix_timestamp, from_unix_timestamp, format_iso8601, parse_iso8601,
    is_valid_hex, is_valid_uuid, is_valid_eth_address, is_valid_btc_address,
    
    # Serialization
    serialize_zk_proof, deserialize_zk_proof,
    serialize_commitment, deserialize_commitment,
    serialize_disclosure_policy, deserialize_disclosure_policy,
    serialize_audit_trail, serialize_audit_event,
    save_proof_json, load_proof_json,
    save_proof_binary, load_proof_binary,
    save_commitment_json, load_commitment_json,
    
    # Errors
    PhantomError, CryptoError, ValidationError, ProofError, NetworkError

# ══════════════════════════════════════════════════════════════════════════════
# INCLUDES
# ══════════════════════════════════════════════════════════════════════════════

# Utility functions (load first - needed by other modules)
include("utils/helpers.jl")

# Cryptographic primitives
include("crypto/primitives.jl")
include("crypto/commitments.jl")
include("crypto/zksnark.jl")
include("crypto/signatures.jl")

# Core functionality
include("core/vulnerability.jl")
include("core/proof.jl")
include("core/disclosure.jl")

# Anonymous reporting
include("anonymous/reporter.jl")
include("anonymous/mixer.jl")

# Audit system
include("audit/trail.jl")
include("audit/verification.jl")

# Integration
include("integration/api.jl")
include("integration/blockchain.jl")

# Serialization
include("utils/serialization.jl")

# ══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

function __init__()
    @info "Phantom v$(PHANTOM_VERSION) - Zero-Knowledge Security Framework"
end

end # module
