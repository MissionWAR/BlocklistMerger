"""
conftest.py - Shared test fixtures for the blocklist merger test suite.

Provides common helpers and ensures clean state between tests.
"""
import os
import tempfile

import pytest

from scripts.compiler import clear_caches


@pytest.fixture(autouse=True)
def _clear_lru_caches():
    """Clear compiler LRU caches between tests to prevent bleed."""
    yield
    clear_caches()


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def make_input_dir(tmp_dir):
    """
    Factory fixture: create an input directory with blocklist files.

    Usage:
        def test_example(make_input_dir):
            input_dir, output_file = make_input_dir({
                "list1.txt": "||example.com^\\n",
            })
    """
    def _make(file_contents: dict[str, str]) -> tuple[str, str]:
        input_dir = os.path.join(tmp_dir, "input")
        os.makedirs(input_dir)
        output_file = os.path.join(tmp_dir, "output.txt")

        for name, content in file_contents.items():
            with open(os.path.join(input_dir, name), "w") as f:
                f.write(content)

        return input_dir, output_file

    return _make
