"""Raw references, typed normalization with field lineage, and entities."""
# Registers the cleaners the store applies to every raw body and event it writes (credentials masked, lone
# surrogates replaced): any code that has typed events has imported this package.
from romulus.evidence import raw_scrub as _raw_scrub  # noqa: F401
