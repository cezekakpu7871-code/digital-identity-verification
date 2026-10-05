import hashlib
import json
import re
from datetime import datetime


class IdentityVerificationError(Exception):
    """Custom exception raised when identity verification fails security checks."""
    pass


class DigitalIdentityVerifier:
    """Core domain service for validating government digital identities."""

    # Standard format for 11-digit National Identity Number (NIN)
    NIN_PATTERN = r"^\d{11}$"

    def __init__(self, system_id: str):
        self.system_id = system_id
        self.audit_logs = []

    def _log_audit_event(self, action: str, status: str, details: str):
        """Records timestamped audit entries for security and compliance."""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "verifier_system": self.system_id,
            "action": action,
            "status": status,
            "details": details
        }
        self.audit_logs.append(event)

    def validate_nin_format(self, nin: str) -> bool:
        """Validates the structure of an 11-digit National Identity Number."""
        if not re.match(self.NIN_PATTERN, nin):
            self._log_audit_event("NIN_VALIDATION", "FAILED", f"Invalid NIN structure: {nin}")
            raise IdentityVerificationError("NIN must consist of exactly 11 digits.")
        return True

    def verify_biometric_hash(self, raw_biometric_data: str, expected_hash: str) -> bool:
        """Verifies biometric payload integrity using SHA-256 hashing."""
        computed_hash = hashlib.sha256(raw_biometric_data.encode()).hexdigest()
        if computed_hash != expected_hash:
            self._log_audit_event("BIOMETRIC_CHECK", "FAILED", "Biometric signature mismatch.")
            return False
        
        self._log_audit_event("BIOMETRIC_CHECK", "PASSED", "Biometric integrity verified.")
        return True

    def verify_identity(self, citizen_name: str, nin: str, biometric_sample: str, expected_bio_hash: str) -> dict:
        """Executes a complete verification pipeline for a citizen record."""
        print(f"\n--- Initiating Verification for: {citizen_name} ---")
        
        # 1. Check Format
        self.validate_nin_format(nin)
        
        # 2. Check Biometric Match
        is_biometric_valid = self.verify_biometric_hash(biometric_sample, expected_bio_hash)
        
        if not is_biometric_valid:
            status = "REJECTED"
            message = "Biometric data mismatch."
        else:
            status = "VERIFIED"
            message = "Identity successfully authenticated."

        self._log_audit_event("FULL_IDENTITY_VERIFICATION", status, f"Citizen: {citizen_name}, NIN: {nin}")
        
        return {
            "citizen_name": citizen_name,
            "nin": nin,
            "status": status,
            "message": message
        }

    def export_audit_trail(self) -> str:
        """Returns JSON-formatted audit logs for regulatory compliance."""
        return json.dumps(self.audit_logs, indent=2)


# --- Demonstration Run ---
if __name__ == "__main__":
    print("==================================================")
    print(" DIGITAL IDENTITY VERIFICATION TOOL (DEMO RUN)")
    print("==================================================\n")

    verifier = DigitalIdentityVerifier(system_id="GOV-ID-NODE-01")

    # Sample biometric data and hash pre-computation
    sample_fingerprint = "raw_fingerprint_minutiae_data_sample_2026"
    valid_hash = hashlib.sha256(sample_fingerprint.encode()).hexdigest()

    # Case 1: Successful Verification
    try:
        result = verifier.verify_identity(
            citizen_name="Chisomeme Ezekakpu",
            nin="12345678901",
            biometric_sample=sample_fingerprint,
            expected_bio_hash=valid_hash
        )
        print(f"Result: {result['status']} - {result['message']}")
    except IdentityVerificationError as e:
        print(f"[VERIFICATION ERROR] {e}")

    # Case 2: Failed Biometric Verification
    try:
        result = verifier.verify_identity(
            citizen_name="Unknown User",
            nin="98765432109",
            biometric_sample="corrupted_sample_data",
            expected_bio_hash=valid_hash
        )
        print(f"Result: {result['status']} - {result['message']}")
    except IdentityVerificationError as e:
        print(f"[VERIFICATION ERROR] {e}")

    # Display Audit Trail
    print("\n--- Compliance Audit Trail ---")
    print(verifier.export_audit_trail())
