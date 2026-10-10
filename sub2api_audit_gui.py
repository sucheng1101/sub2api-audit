#!/usr/bin/env python3
"""Compatibility launcher for the unified Sub2API audit tool."""

from sub2api_audit import *  # noqa: F401,F403
from sub2api_audit import main


if __name__ == "__main__":
    raise SystemExit(main())
