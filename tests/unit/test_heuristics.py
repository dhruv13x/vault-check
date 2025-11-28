import pytest
from vault_check.heuristics import HeuristicsEngine
from vault_check.verifiers.database import DatabaseVerifier
from vault_check.verifiers.redis import RedisVerifier
from vault_check.verifiers.s3 import S3Verifier
from vault_check.verifiers.smtp import SMTPVerifier

def test_heuristics_match_database():
    assert HeuristicsEngine.match("postgres://user:pass@host:5432/db") == DatabaseVerifier
    assert HeuristicsEngine.match("postgresql://user:pass@host:5432/db") == DatabaseVerifier
    assert HeuristicsEngine.match("postgres+asyncpg://user:pass@host:5432/db") == DatabaseVerifier
    assert HeuristicsEngine.match("sqlite://test.db") == DatabaseVerifier

def test_heuristics_match_redis():
    assert HeuristicsEngine.match("redis://localhost:6379") == RedisVerifier
    assert HeuristicsEngine.match("rediss://localhost:6379") == RedisVerifier

def test_heuristics_match_s3():
    assert HeuristicsEngine.match("s3://my-bucket") == S3Verifier
    assert HeuristicsEngine.match("s3://my-bucket/path/to/key") == S3Verifier

def test_heuristics_match_smtp():
    assert HeuristicsEngine.match("smtp://smtp.gmail.com") == SMTPVerifier
    assert HeuristicsEngine.match("smtps://smtp.gmail.com") == SMTPVerifier
    assert HeuristicsEngine.match("smtp://user:pass@host:587") == SMTPVerifier

def test_heuristics_no_match():
    assert HeuristicsEngine.match("invalid_url") is None
    assert HeuristicsEngine.match("http://google.com") is None  # Currently not matching generic HTTP
    assert HeuristicsEngine.match("random_string") is None
    assert HeuristicsEngine.match(123) is None
