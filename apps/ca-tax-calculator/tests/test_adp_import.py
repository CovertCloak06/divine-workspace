"""Tests for ADP import module."""

import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adp_import import _clean_amount, parse_adp_csv, apply_adp_data


def test_clean_amount_basic():
    assert _clean_amount("1234.56") == 1234.56
    assert _clean_amount("$1,234.56") == 1234.56
    assert _clean_amount("$85,000.00") == 85000.0


def test_clean_amount_parentheses():
    """Negative amounts in accounting format."""
    assert _clean_amount("(123.45)") == 123.45  # abs value


def test_clean_amount_empty():
    assert _clean_amount("") == 0.0
    assert _clean_amount("  ") == 0.0
    assert _clean_amount(None) == 0.0


def test_clean_amount_invalid():
    assert _clean_amount("N/A") == 0.0
    assert _clean_amount("abc") == 0.0


def test_parse_adp_csv():
    """Test parsing a mock ADP CSV export."""
    csv_content = """Gross Pay,Regular Hours,OT Hours,Rate,Federal Tax,CA State Tax,Medical Employee
"$4,000.00",80,10,25.00,"$600.00","$200.00","$250.00"
"$4,500.00",80,15,25.00,"$700.00","$230.00","$250.00"
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(csv_content)
        f.flush()
        result = parse_adp_csv(f.name)

    os.unlink(f.name)

    assert "error" not in result
    # Gross should be summed: 4000 + 4500
    assert result["gross_income"] == 8500.0
    # Rate should be from last row (not summed)
    assert result["hourly_rate"] == 25.0
    # Health premium combined
    assert result["health_premium"] == 500.0
    # Federal withheld summed
    assert result["federal_withheld"] == 1300.0
    assert result["_pay_periods"] == 2


def test_parse_adp_csv_missing_file():
    result = parse_adp_csv("/nonexistent/file.csv")
    assert "error" in result


def test_parse_adp_csv_wrong_extension():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"test")
    result = parse_adp_csv(f.name)
    os.unlink(f.name)
    assert "error" in result


def test_apply_adp_data():
    adp = {
        "gross_income": 85000,
        "hourly_rate": 25,
        "overtime_hours": 10,
        "health_premium": 6000,
        "federal_withheld": 12000,
        "state_withheld": 4000,
    }
    calc = apply_adp_data(adp)
    assert calc["gross_income"] == 85000
    assert calc["hourly_rate"] == 25
    assert calc["health_premium"] == 6000
    # Withholding stored with underscore prefix
    assert calc["_federal_withheld"] == 12000
    assert calc["_state_withheld"] == 4000


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {test.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
