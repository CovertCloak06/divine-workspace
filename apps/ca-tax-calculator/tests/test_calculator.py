"""Tests for CA Tax Calculator - Updated for 2025 values."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca_tax_calculator import (
    calculate_overtime_pay,
    calculate_prevailing_wage_ot,
    calculate_premium_deduction,
    calculate_itemized_deductions,
    calculate_federal_tax,
    calculate_ca_state_tax,
    calculate_payroll_taxes,
    full_tax_summary,
    _calculate_salt_cap,
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


def test_prevailing_wage_ot_basic():
    """Prevailing wage: $45/hr base + $20/hr fringe, 40 reg + 10 OT hours.

    Regular: 40 x $45 = $1,800
    OT: 10 x ($45 x 1.5) = 10 x $67.50 = $675
    OT premium: 10 x ($45 x 0.5) = $225  (the extra above straight time)
    Fringe: 50 hrs x $20 = $1,000
    Total base: $1,800 + $675 = $2,475
    Gross: $2,475 + $1,000 = $3,475
    """
    r = calculate_prevailing_wage_ot(
        base_rate=45, fringe_rate=20,
        regular_hours=40, ot_hours=10,
    )
    assert r["prevailing_wage_rate"] == 65.0
    assert r["regular_base_pay"] == 1800.0
    assert r["ot_base_rate"] == 67.5
    assert r["ot_base_pay"] == 675.0
    assert r["ot_premium_amount"] == 225.0
    assert r["total_fringe"] == 1000.0
    assert r["total_base_pay"] == 2475.0
    assert r["gross_compensation"] == 3475.0
    assert r["total_premium_ot"] == 225.0


def test_prevailing_wage_ot_with_dt():
    """Prevailing wage with double time (Sunday).

    Base $50, Fringe $15
    Regular: 32 hrs x $50 = $1,600
    Saturday (1.5x): 8 hrs x $75 = $600, premium = 8 x $25 = $200
    Sunday (2x): 8 hrs x $100 = $800, premium = 8 x $50 = $400
    Total hours: 48
    Fringe: 48 x $15 = $720
    """
    r = calculate_prevailing_wage_ot(
        base_rate=50, fringe_rate=15,
        regular_hours=32, saturday_hours=8, sunday_hours=8,
    )
    assert r["regular_base_pay"] == 1600.0
    assert r["ot_base_pay"] == 600.0     # Saturday 1.5x
    assert r["dt_base_pay"] == 800.0     # Sunday 2x
    assert r["ot_premium_amount"] == 200.0
    assert r["dt_premium_amount"] == 400.0
    assert r["total_premium_ot"] == 600.0
    assert r["total_fringe"] == 720.0
    assert r["total_hours"] == 48.0
    assert r["gross_compensation"] == 3720.0  # 1600+600+800+720


def test_prevailing_wage_fringe_cash_taxable():
    """When fringe paid as cash, taxable wages include fringe."""
    r = calculate_prevailing_wage_ot(
        base_rate=45, fringe_rate=20,
        regular_hours=40, fringe_paid_as_cash=True,
    )
    # Base: 40 x 45 = 1800, Fringe: 40 x 20 = 800
    assert r["total_base_pay"] == 1800.0
    assert r["total_fringe"] == 800.0
    # Cash fringe is taxable
    assert r["taxable_wages"] == 2600.0  # 1800 + 800
    assert r["fringe_paid_as_cash"] is True


def test_prevailing_wage_fringe_benefits_not_taxable():
    """When fringe paid as benefits, taxable wages exclude fringe."""
    r = calculate_prevailing_wage_ot(
        base_rate=45, fringe_rate=20,
        regular_hours=40, fringe_paid_as_cash=False,
    )
    assert r["taxable_wages"] == 1800.0  # only base pay
    assert r["fringe_paid_as_cash"] is False


def test_premium_deduction_employee():
    result = calculate_premium_deduction(6000, 4000)
    assert result["out_of_pocket"] == 2000.0
    assert "Schedule A" in result["deduction_type"]


def test_premium_deduction_self_employed():
    result = calculate_premium_deduction(6000, 0, is_self_employed=True)
    assert result["deductible_amount"] == 6000.0
    assert "Schedule 1" in result["deduction_type"]


def test_salt_cap_under_phaseout():
    """SALT cap is $40k for income under $500k."""
    cap = _calculate_salt_cap(100_000)
    assert cap == 40_000


def test_salt_cap_phaseout():
    """SALT cap reduces by 30% of excess over $500k."""
    # At $550k: reduction = 0.30 * 50000 = 15000, cap = 40000 - 15000 = 25000
    cap = _calculate_salt_cap(550_000)
    assert cap == 25_000


def test_salt_cap_floor():
    """SALT cap floors at $10k after full phaseout."""
    cap = _calculate_salt_cap(700_000)
    assert cap == 10_000


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
    # SALT capped at $40k (OBBB 2025), so full $15k is deductible
    assert result["salt_cap"] == 40_000
    assert result["salt_deductible_after_cap"] == 15000.0
    # Total: 4000 + 12000 + 15000 + 3000 = 34000
    assert result["total_itemized"] == 34000.0


def test_federal_tax_single_85k():
    """Manual bracket calc for $85k single, $15,750 standard deduction.

    Taxable: $85,000 - $15,750 = $69,250
    10% on $11,925 = $1,192.50
    12% on ($48,475 - $11,925) = $36,550 * 0.12 = $4,386.00
    22% on ($69,250 - $48,475) = $20,775 * 0.22 = $4,570.50
    Total = $10,149.00
    """
    result = calculate_federal_tax(85000, 15750, "single")
    assert result["taxable_income"] == 69250.0
    assert result["federal_tax"] == 10149.0


def test_ca_state_tax_85k():
    """Manual bracket calc for $85k single, $5,706 CA standard deduction.

    Taxable: $85,000 - $5,706 = $79,294
    1% on $11,079 = $110.79
    2% on ($26,264 - $11,079) = $15,185 * 0.02 = $303.70
    4% on ($41,452 - $26,264) = $15,188 * 0.04 = $607.52
    6% on ($57,542 - $41,452) = $16,090 * 0.06 = $965.40
    8% on ($72,724 - $57,542) = $15,182 * 0.08 = $1,214.56
    9.3% on ($79,294 - $72,724) = $6,570 * 0.093 = $611.01
    Total = $3,812.98
    """
    result = calculate_ca_state_tax(85000, 5706, "single")
    assert result["ca_taxable_income"] == 79294.0
    assert result["ca_state_tax"] == 3812.98


def test_payroll_taxes():
    result = calculate_payroll_taxes(100000)
    assert result["social_security"] == 6200.0  # 100000 * 0.062
    assert result["medicare"] == 1450.0  # 100000 * 0.0145
    assert result["medicare_surtax"] == 0.0  # under 200k
    assert result["ca_sdi"] == 1200.0  # 100000 * 0.012 (2025 rate)


def test_payroll_taxes_high_earner():
    result = calculate_payroll_taxes(300000, "single")
    # SS: min(300000, 176100) * 0.062 = 10918.20
    assert result["social_security"] == 10918.20
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


def test_no_double_deduction_self_employed():
    """Verify self-employed health deduction is not applied twice."""
    result_se = full_tax_summary(
        gross_income=100000,
        is_self_employed=True,
        health_premium=10000,
    )
    # AGI should be 90000 (100k - 10k health deduction)
    # Federal taxable = 90000 - 15750 standard = 74250
    assert result_se["federal"]["taxable_income"] == 74250.0


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
