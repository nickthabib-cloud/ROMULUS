"""Investigator replay: frozen production briefs replayed through the model decision path.

``export`` rebuilds the exact briefs a hunt's investigator sent, from a read-only copy of the store.
``runner`` sends them through the production Ollama client, decision schema and validation, and records
schema validity, validation outcome, latency and token rates. Decision accuracy against expected decisions
is scored by the eval-custodian (``eval/``), never here.
"""
