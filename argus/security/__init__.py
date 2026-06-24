"""Security sub-package: prompt input guard.

Threat modeling is by nature an adversarial domain: the documents we analyze may themselves
contain injection payloads. The input guard keeps untrusted input separated from instructions.
"""
