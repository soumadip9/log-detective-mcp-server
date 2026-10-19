"""Tests for Phase 3: get_log_context tool."""

import pytest
from log_detective.tools import get_log_context


def test_get_log_context_basic():
    sample = """Line 1
Line 2
Line 3
Line 4
Line 5
Line 6
Line 7
Line 8
Line 9
Line 10"""
    result = get_log_context(sample, target_line=5, context_size=2)
    assert result["target_line"] == 5
    assert result["start_line"] == 3
    assert result["end_line"] == 7
    assert len(result["lines"]) == 5
    assert result["lines"][2]["line_number"] == 5
    assert result["lines"][2]["is_target"] is True
    assert ">     5 | Line 5" in result["formatted"]


def test_get_log_context_boundary_clamping():
    sample = "Line 1\nLine 2\nLine 3"
    # Target line at beginning
    res_start = get_log_context(sample, target_line=1, context_size=5)
    assert res_start["start_line"] == 1
    assert res_start["end_line"] == 3
    assert len(res_start["lines"]) == 3

    # Target line at end
    res_end = get_log_context(sample, target_line=3, context_size=5)
    assert res_end["start_line"] == 1
    assert res_end["end_line"] == 3


def test_get_log_context_out_of_bounds_target_line():
    sample = "Line 1\nLine 2"
    with pytest.raises(ValueError) as exc:
        get_log_context(sample, target_line=0)
    assert "out of bounds" in str(exc.value)

    with pytest.raises(ValueError) as exc2:
        get_log_context(sample, target_line=99)
    assert "out of bounds" in str(exc2.value)


def test_get_log_context_invalid_types():
    sample = "Line 1\nLine 2"
    with pytest.raises(TypeError):
        get_log_context(sample, target_line="invalid")  # type: ignore

    with pytest.raises(TypeError):
        get_log_context(sample, target_line=1, context_size="invalid")  # type: ignore


def test_get_log_context_context_size_capped():
    lines = [f"Line {i}" for i in range(1, 200)]
    sample = "\n".join(lines)
    # Requested context size 100 exceeds MAX_CONTEXT_SIZE (50)
    result = get_log_context(sample, target_line=100, context_size=100)
    assert result["context_size"] == 50
    assert result["start_line"] == 50
    assert result["end_line"] == 150
