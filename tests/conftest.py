import pytest

from scripts.lab import Lab


def pytest_addoption(parser):
    parser.addoption(
        "--require-denial-on-vulnerable",
        action="store_true",
        help="Demonstrate the security regression failing against the original lab",
    )


@pytest.fixture(scope="session")
def lab(request):
    mode = (
        "vulnerable-gate"
        if request.config.getoption("--require-denial-on-vulnerable")
        else "baseline"
    )
    environment = Lab(f"reports/{mode}")
    try:
        yield environment.start()
    finally:
        try:
            if environment.zap_url and environment.observations:
                environment.export()
        finally:
            environment.close()
