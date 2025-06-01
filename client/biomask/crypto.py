from cryptography.x509.base import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import base64


def extract_uploader_id(cert_pem: bytes) -> str:
    cert = load_pem_x509_certificate(cert_pem, default_backend())
    subject = cert.subject.rfc4514_string()
    subject_parts = sorted(subject.split(','), key=lambda x: 0 if x.strip().startswith("CN=") else 1)
    normalized_subject = ",".join(subject_parts)
    issuer = cert.issuer.rfc4514_string()
    uploader_id = f"x509::/{normalized_subject}::/{issuer}"
    # Convert to base64 as expected by the chaincode
    return base64.b64encode(uploader_id.encode()).decode()
