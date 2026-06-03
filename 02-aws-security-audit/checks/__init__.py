"""
Audit check modules for the AWS Security Misconfiguration Audit tool.

Each check module exposes a ``run(session)`` function that accepts a configured
``boto3.Session`` and returns a list of finding dictionaries. Grouping checks by
AWS service keeps the tool easy to extend: add a ``run(session)`` to an existing
module, or create a new module and append it to ``CHECK_MODULE_NAMES``.

Submodules are imported lazily via :func:`get_all_check_modules` so that the
reporting/demo code path (which only needs :mod:`checks.finding`) does not
require ``boto3``/``botocore`` to be installed.
"""

import importlib

# Service modules executed, in order, during a live audit.
CHECK_MODULE_NAMES = ["iam_checks", "s3_checks", "ec2_checks", "cloudtrail_checks"]


def get_all_check_modules():
    """Import and return the check modules (requires boto3/botocore)."""
    return [importlib.import_module(f"{__name__}.{name}") for name in CHECK_MODULE_NAMES]


__all__ = ["CHECK_MODULE_NAMES", "get_all_check_modules"]
