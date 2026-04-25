import re

REQUIRED_COLUMNS = [
    "incident_id", 
    "file_name", 
    "data_owner", 
    "ssn", 
    "policy_action", 
    "incident_notes"
]

REDACT_KEYWORDS = ["password", "secret", "token", "credential"]
REDACTED_PLACEHOLDER = "[REDACTED]"
BAD_INPUT_MESSAGE = "Bad input"

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SSN_REGEX = re.compile(r"^\d{3}-\d{2}-\d{4}$")
KEYWORD_REGEX = re.compile(rf"\b({'|'.join(REDACT_KEYWORDS)})\b", re.IGNORECASE)