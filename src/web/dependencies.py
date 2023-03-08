from typing import Generator
from generic import ApplicationContext

appcntx = ApplicationContext.instance()


def get_app_cntxt() -> Generator[ApplicationContext, None, None]:
    """Return the application context."""
    return appcntx
