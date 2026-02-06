#!/usr/bin/env python3
"""CA Tax Calculator - CLI Interface

Usage:
    python main.py                          # Interactive mode
    python main.py --quick 85000            # Quick estimate for $85k income
    python main.py --ot 25 40 10            # OT calc: $25/hr, 40 reg, 10 OT hrs
"""

import argparse
import json
import sys

from ca_tax_calculator import (
    calculate_overtime_pay,
    calculate_premium_deduction,
    full_tax_summary,
    STANDARD_DEDUCTION,
)


def fmt(amount: float) -> str:
    """Format dollar amount."""
    return f"${amount:,.2f}"


def print_section(title: str):
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")


def print_row(label: str, value, width: int = 35):
    print(f"  {label:<{width}} {value}")


def get_dollar_input(prompt: str, default: float = 0.0) -> float:
    """Safely get a dollar amount from user input."""
    raw = input(prompt).strip().replace(",", "").replace("$", "")
    if not raw:
        return default
    try:
        value = float(raw)
        if value < 0:
            print("  (Using 0 - negative values not allowed)")
            return 0.0
        return value
    except ValueError:
        print(f"  (Invalid number '{raw}', using {default})")
        return default


def run_interactive():
    """Interactive mode - walk through all inputs."""
    print_section("CA TAX CALCULATOR")
    print("  Calculates premium deductions, OT rates,")
    print("  and estimated tax for California returns.\n")

    # Filing status
    print("  Filing status:")
    print("    1. Single")
    print("    2. Married filing jointly")
    print("    3. Head of household")
    choice = input("\n  Select (1-3) [1]: ").strip() or "1"
    status_map = {"1": "single", "2": "married", "3": "head_of_household"}
    filing_status = status_map.get(choice, "single")

    # Income
    print_section("INCOME")
    gross = get_dollar_input("  Annual gross income: $")

    # Employment type
    is_se = input("  Self-employed? (y/n) [n]: ").strip().lower() == "y"

    # Overtime
    print_section("OVERTIME (optional)")
    has_ot = input("  Calculate overtime pay? (y/n) [n]: ").strip().lower() == "y"
    hourly = reg_hrs = ot_hrs = dt_hrs = 0.0
    if has_ot:
        hourly = get_dollar_input("  Hourly rate: $")
        reg_hrs = get_dollar_input("  Regular hours/week: ", 40.0)
        ot_hrs = get_dollar_input("  Overtime hours (1.5x): ")
        dt_hrs = get_dollar_input("  Double-time hours (2x): ")

    # Health insurance
    print_section("HEALTH INSURANCE PREMIUMS")
    premium = get_dollar_input("  Annual health insurance premium: $")
    employer_contrib = 0.0
    if premium > 0 and not is_se:
        employer_contrib = get_dollar_input("  Employer contribution: $")

    # Deductions
    print_section("DEDUCTIONS (for itemizing)")
    medical = get_dollar_input("  Total medical expenses: $")
    mortgage = get_dollar_input("  Mortgage interest paid: $")
    salt = get_dollar_input("  State & local taxes paid: $")
    charity = get_dollar_input("  Charitable donations: $")

    # Calculate
    result = full_tax_summary(
        gross_income=gross,
        filing_status=filing_status,
        health_premium=premium,
        employer_health_contribution=employer_contrib,
        is_self_employed=is_se,
        medical_expenses=medical,
        mortgage_interest=mortgage,
        state_local_taxes=salt,
        charitable_donations=charity,
        hourly_rate=hourly,
        regular_hours=reg_hrs,
        overtime_hours=ot_hrs,
        double_time_hours=dt_hrs,
    )

    # Display results
    display_results(result, filing_status)


def display_results(result: dict, filing_status: str = "single"):
    """Pretty-print the tax calculation results."""

    if "overtime" in result:
        ot = result["overtime"]
        print_section("OVERTIME BREAKDOWN")
        print_row("Hourly rate:", fmt(ot["hourly_rate"]))
        print_row("Regular pay:", f"{ot['regular_hours']} hrs x {fmt(ot['hourly_rate'])} = {fmt(ot['regular_pay'])}")
        print_row("OT pay (1.5x):", f"{ot['overtime_hours']} hrs x {fmt(ot['ot_rate'])} = {fmt(ot['overtime_pay'])}")
        print_row("Double-time (2x):", f"{ot['double_time_hours']} hrs x {fmt(ot['double_time_rate'])} = {fmt(ot['double_time_pay'])}")
        print_row("Gross pay:", fmt(ot["gross_pay"]))

    if "premium_deduction" in result:
        pd = result["premium_deduction"]
        print_section("HEALTH PREMIUM DEDUCTION")
        print_row("Annual premium:", fmt(pd["annual_premium"]))
        print_row("Employer contribution:", fmt(pd["employer_contribution"]))
        print_row("Your cost:", fmt(pd["out_of_pocket"]))
        print_row("Deduction type:", pd["deduction_type"])
        print(f"\n  Note: {pd['note']}")

    dc = result["deduction_choice"]
    print_section("DEDUCTION COMPARISON")
    print_row("Standard deduction:", fmt(dc["standard_deduction"]))
    print_row("Itemized total:", fmt(dc["itemized_total"]))
    print_row("Using:", dc["using"].upper())
    print_row("Deduction amount:", fmt(dc["federal_deduction_amount"]))

    fed = result["federal"]
    print_section("FEDERAL INCOME TAX")
    print_row("Taxable income:", fmt(fed["taxable_income"]))
    print_row("Federal tax:", fmt(fed["federal_tax"]))
    print_row("Effective rate:", f"{fed['effective_rate']}%")

    ca = result["california"]
    print_section("CALIFORNIA STATE TAX")
    print_row("CA taxable income:", fmt(ca["ca_taxable_income"]))
    print_row("CA state tax:", fmt(ca["ca_state_tax"]))
    print_row("CA effective rate:", f"{ca['ca_effective_rate']}%")

    pr = result["payroll"]
    print_section("PAYROLL TAXES")
    print_row("Social Security:", fmt(pr["social_security"]))
    print_row("Medicare:", fmt(pr["medicare"]))
    if pr["medicare_surtax"] > 0:
        print_row("Medicare surtax:", fmt(pr["medicare_surtax"]))
    print_row("CA SDI:", fmt(pr["ca_sdi"]))
    print_row("Total payroll:", fmt(pr["total_payroll_taxes"]))

    s = result["summary"]
    print_section("TOTAL TAX SUMMARY")
    print_row("Gross income:", fmt(s["gross_income"]))
    print_row("Federal tax:", fmt(s["total_federal_tax"]))
    print_row("CA state tax:", fmt(s["total_ca_state_tax"]))
    print_row("Payroll taxes:", fmt(s["total_payroll_taxes"]))
    print(f"  {'-' * 45}")
    print_row("Total tax burden:", fmt(s["total_tax_burden"]))
    print_row("Estimated take-home:", fmt(s["estimated_take_home"]))
    print_row("Overall effective rate:", f"{s['overall_effective_rate']}%")
    print()


def quick_estimate(income: float, filing_status: str = "single"):
    """Quick tax estimate with standard deduction only."""
    result = full_tax_summary(gross_income=income, filing_status=filing_status)
    display_results(result, filing_status)


def ot_calc(hourly: float, regular: float, overtime: float,
            double_time: float = 0.0):
    """Quick overtime calculation."""
    ot = calculate_overtime_pay(hourly, regular, overtime, double_time)
    print_section("OVERTIME CALCULATION")
    print_row("Hourly rate:", fmt(ot["hourly_rate"]))
    print_row("Regular pay:", f"{ot['regular_hours']} hrs x {fmt(ot['hourly_rate'])} = {fmt(ot['regular_pay'])}")
    print_row("OT pay (1.5x):", f"{ot['overtime_hours']} hrs x {fmt(ot['ot_rate'])} = {fmt(ot['overtime_pay'])}")
    if ot["double_time_hours"] > 0:
        print_row("Double-time (2x):", f"{ot['double_time_hours']} hrs x {fmt(ot['double_time_rate'])} = {fmt(ot['double_time_pay'])}")
    print(f"  {'-' * 45}")
    print_row("Gross pay:", fmt(ot["gross_pay"]))
    print()


def main():
    parser = argparse.ArgumentParser(
        description="CA Tax Calculator - Premium, deductible, and OT rate calculator"
    )
    parser.add_argument("--quick", type=float, metavar="INCOME",
                        help="Quick estimate for given annual income")
    parser.add_argument("--status", choices=["single", "married", "head_of_household"],
                        default="single", help="Filing status (default: single)")
    parser.add_argument("--ot", nargs=3, type=float, metavar=("RATE", "REG_HRS", "OT_HRS"),
                        help="Overtime calc: hourly_rate regular_hours overtime_hours")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")

    args = parser.parse_args()

    if args.ot:
        if args.json:
            result = calculate_overtime_pay(args.ot[0], args.ot[1], args.ot[2])
            print(json.dumps(result, indent=2))
        else:
            ot_calc(args.ot[0], args.ot[1], args.ot[2])
    elif args.quick:
        if args.json:
            result = full_tax_summary(gross_income=args.quick,
                                      filing_status=args.status)
            print(json.dumps(result, indent=2, default=str))
        else:
            quick_estimate(args.quick, args.status)
    else:
        run_interactive()


if __name__ == "__main__":
    main()
