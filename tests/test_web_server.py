from subprocess import call

import pytest
from src.verifier import TokenStatusListVerifier

@pytest.fixture(scope="session", autouse=True)
def create_issuer():
    call("docker-compose build && docker-compose up -d")
    yield
    call("docker-compose down")

ISSUER = "http://localhost:3001"