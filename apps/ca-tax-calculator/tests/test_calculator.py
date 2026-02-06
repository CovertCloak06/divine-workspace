"""Tests for CA Tax Calculator."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca_tax_calculator import (
    calculate_overtime_pay,
    calculate_premium_deduction,
    calculate_itemized_deductions,
    calculate_federal_tax,
    calculate_ca_state_tax,
    calculate_payroll_taxes,
    full_tax_summary,
)


def test_overtime_basic():
    result = calculate_overtime_pay(25.0, 40, 10)
    assert result["regular_pay"] == 1000.0
    assert result["ot_rate"] == 37.5
    assert result["overtime_pay"] == 375.0
    assert result["gross_pay"] == 1375.0


def test_overtime_with_double_time():
    result = calculate_overtime_pay(30.0, 40, 8, 4)
    assert result["regular_pay"] == 1200.0
    assert result["overtime_pay"] == 360.0  # 8 * 45
    assert result["double_time_pay"] == 240.0  # 4 * 60
    assert result["gross_pay"] == 1800.0


def test_premium_deduction_employee():
    result = calculate_premium_deduction(6000, 4000)
    assert result["out_of_pocket"] == 2000.0
    assert "Schedule A" in result["deduction_type"]


def test_premium_deduction_self_employed():
    result = calculate_premium_deduction(6000, 0, is_self_employed=True)
    assert result["deductible_amount"] == 6000.0
    assert "Schedule 1" in result["deduction_type"]


def test_itemized_deductions():
    result = calculate_itemized_deductions(
        medical_expenses=10000,
        agi=80000,
        mortgage_interest=12000,
        state_local_taxes=15000,
        charitable_donations=3000,
    )
    # Medical threshold: 80000 * 0.075 = 6000, deductible = 4000
    assert result["medical_deductible"] == 4000.0
    # SALT capped at 10000
    assert result["salt_deductible_after_cap"] == 10000.0
    assert result["total_itemized"] == 29000.0  # 4000 + 12000 + 10000 + 3000


def test_federal_tax_single():
    result = calculate_federal_tax(100000, 14600, "single")
    assert result["taxable_income"] == 85400.0
    assert result["federal_tax"] > 0


def test_ca_state_tax():
    result = calculate_ca_state_tax(100000, 5540, "single")
    assert result["ca_taxable_income"] == 94460.0
    assert result["ca_state_tax"] > 0


def test_payroll_taxes():
    result = calculate_payroll_taxes(100000)
    assert result["social_security"] == 6200.0  # 100000 * 0.062
    assert result["medicare"] == 1450.0  # 100000 * 0.0145
    assert result["medicare_surtax"] == 0.0  # under 200k
    assert result["ca_sdi"] == 1100.0  # 100000 * 0.011


def test_payroll_taxes_high_earner():
    result = calculate_payroll_taxes(300000, "single")
    assert result["social_security"] == 10453.20  # capped at 168600
    assert result["medicare_surtax"] == 900.0  # (300000-200000) * 0.009


def test_full_summary():
    result = full_tax_summary(gross_income=85000, filing_status="single")
    assert "federal" in result
    assert "california" in result
    assert "payroll" in result
    assert "summary" in result
    assert result["summary"]["gross_income"] == 85000
    assert result["summary"]["estimated_take_home"] > 0


def test_full_summary_with_ot():
    result = full_tax_summary(
        gross_income=85000,
        hourly_rate=25,
        regular_hours=40,
        overtime_hours=10,
    )
    assert "overtime" in result
    assert result["overtime"]["gross_pay"] == 1375.0


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
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
