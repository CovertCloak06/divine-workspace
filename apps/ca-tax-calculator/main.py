#!/usr/bin/env python3
"""CA Tax Calculator - CLI Interface

Usage:
    python main.py --pw                     # Prevailing wage OT calculator (main feature)
    python main.py --pw-quick 45 20 40 10 4 # Quick PW OT: base fringe reg ot dt
    python main.py                          # Full tax return calculator (interactive)
    python main.py --quick 85000            # Quick tax estimate for $85k income
    python main.py --ot 25 40 10            # Simple OT calc: $25/hr, 40 reg, 10 OT hrs
    python main.py --import-adp stub.csv    # Import from ADP CSV export
    python main.py --adp                    # Guided ADP pay stub entry
    python main.py --profile default        # Load saved profile
    python main.py --history                # View past calculations
"""

from __future__ import annotations

import argparse
import json
import sys

from ca_tax_calculator import (
    calculate_overtime_pay,
    calculate_prevailing_wage_ot,
    calculate_premium_deduction,
    full_tax_summary,
    STANDARD_DEDUCTION,
)
from storage import (
    save_draft, load_draft, clear_draft, format_draft_summary,
    save_profile, load_profile, list_profiles,
    save_result, list_results,
)
from adp_import import parse_adp_csv, guided_adp_entry, apply_adp_data


def fmt(amount: float) -> str:
    """Format dollar amount."""
    return f"${amount:,.2f}"


def print_section(title: str):
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")


def print_row(label: str, value, width: int = 35):
    print(f"  {label:<{width}} {value}")


def get_dollar_input(prompt: str, default: float = 0.0, prefill: float = None) -> float:
    """Safely get a dollar amount from user input, with optional pre-fill."""
    if prefill is not None and prefill > 0:
        display = f"{prompt}[{prefill:,.2f}] "
    else:
        display = prompt
    raw = input(display).strip().replace(",", "").replace("$", "")
    if not raw:
        return prefill if (prefill is not None and prefill > 0) else default
    try:
        value = float(raw)
        if value < 0:
            print("  (Using 0 - negative values not allowed)")
            return 0.0
        return value
    except ValueError:
        print(f"  (Invalid number '{raw}', using {default})")
        return default


def get_yn_input(prompt: str, default: str = "n", prefill: bool = None) -> bool:
    """Get yes/no input with optional pre-fill."""
    if prefill is not None:
        hint = "Y/n" if prefill else "y/N"
    else:
        hint = "y/n"
    raw = input(f"{prompt}({hint}) [{default}]: ").strip().lower()
    if not raw:
        return prefill if prefill is not None else (default == "y")
    return raw == "y"


def run_interactive(prefill: dict = None):
    """Interactive mode with auto-save and optional pre-filled values."""
    pf = prefill or {}
    fields = {}

    print_section("CA TAX CALCULATOR")
    print("  Calculates premium deductions, OT rates,")
    print("  and estimated tax for California returns.")
    if pf:
        source = pf.pop("_source", "saved data")
        print(f"\n  Pre-filled from: {source}")
        print("  Press Enter to accept [shown values] or type new ones.\n")
    else:
        print()

    # Filing status
    print("  Filing status:")
    print("    1. Single")
    print("    2. Married filing jointly")
    print("    3. Head of household")
    status_map = {"1": "single", "2": "married", "3": "head_of_household"}
    reverse_map = {v: k for k, v in status_map.items()}
    default_choice = reverse_map.get(pf.get("filing_status", ""), "1")
    choice = input(f"\n  Select (1-3) [{default_choice}]: ").strip() or default_choice
    filing_status = status_map.get(choice, "single")
    fields["filing_status"] = filing_status
    save_draft(fields)

    # Income
    print_section("INCOME")
    gross = get_dollar_input("  Annual gross income: $", prefill=pf.get("gross_income"))
    fields["gross_income"] = gross
    save_draft(fields)

    # Employment type
    is_se = get_yn_input("  Self-employed? ", prefill=pf.get("is_self_employed"))
    fields["is_self_employed"] = is_se
    save_draft(fields)

    # Overtime
    print_section("OVERTIME (optional)")
    has_ot_prefill = pf.get("hourly_rate", 0) > 0
    has_ot = get_yn_input("  Calculate overtime pay? ", prefill=has_ot_prefill)
    hourly = reg_hrs = ot_hrs = dt_hrs = 0.0
    if has_ot:
        hourly = get_dollar_input("  Hourly rate: $", prefill=pf.get("hourly_rate"))
        reg_hrs = get_dollar_input("  Regular hours/week: ", 40.0, prefill=pf.get("regular_hours"))
        ot_hrs = get_dollar_input("  Overtime hours (1.5x): ", prefill=pf.get("overtime_hours"))
        dt_hrs = get_dollar_input("  Double-time hours (2x): ", prefill=pf.get("double_time_hours"))
    fields.update(hourly_rate=hourly, regular_hours=reg_hrs,
                  overtime_hours=ot_hrs, double_time_hours=dt_hrs)
    save_draft(fields)

    # Health insurance
    print_section("HEALTH INSURANCE PREMIUMS")
    premium = get_dollar_input("  Annual health insurance premium: $",
                               prefill=pf.get("health_premium"))
    employer_contrib = 0.0
    if premium > 0 and not is_se:
        employer_contrib = get_dollar_input("  Employer contribution: $",
                                           prefill=pf.get("employer_health_contribution"))
    fields.update(health_premium=premium, employer_health_contribution=employer_contrib)
    save_draft(fields)

    # Deductions
    print_section("DEDUCTIONS (for itemizing)")
    medical = get_dollar_input("  Total medical expenses: $",
                               prefill=pf.get("medical_expenses"))
    mortgage = get_dollar_input("  Mortgage interest paid: $",
                                prefill=pf.get("mortgage_interest"))
    salt = get_dollar_input("  State & local taxes paid: $",
                            prefill=pf.get("state_local_taxes"))
    charity = get_dollar_input("  Charitable donations: $",
                               prefill=pf.get("charitable_donations"))
    fields.update(medical_expenses=medical, mortgage_interest=mortgage,
                  state_local_taxes=salt, charitable_donations=charity)
    save_draft(fields)

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

    # Show withholding comparison if we have ADP data
    fed_withheld = pf.get("_federal_withheld", 0)
    state_withheld = pf.get("_state_withheld", 0)
    if fed_withheld > 0 or state_withheld > 0:
        print_section("WITHHOLDING COMPARISON (vs ADP)")
        if fed_withheld > 0:
            diff = fed_withheld - result["federal"]["federal_tax"]
            status = "OVERPAID (refund expected)" if diff > 0 else "UNDERPAID (may owe)"
            print_row("ADP Federal withheld:", fmt(fed_withheld))
            print_row("Calculated Federal tax:", fmt(result["federal"]["federal_tax"]))
            print_row("Difference:", f"{fmt(abs(diff))} - {status}")
        if state_withheld > 0:
            diff = state_withheld - result["california"]["ca_state_tax"]
            status = "OVERPAID (refund expected)" if diff > 0 else "UNDERPAID (may owe)"
            print_row("ADP CA State withheld:", fmt(state_withheld))
            print_row("Calculated CA tax:", fmt(result["california"]["ca_state_tax"]))
            print_row("Difference:", f"{fmt(abs(diff))} - {status}")
        print()

    # Save result and clear draft
    save_result(result, fields)
    clear_draft()
    print("  Result saved. View past calculations with: python main.py --history")

    return fields


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


def pw_ot_interactive():
    """Prevailing wage OT calculator - guided mode."""
    print_section("PREVAILING WAGE OT CALCULATOR")
    print("  California DIR prevailing wage overtime breakdown.")
    print("  OT premium applies to BASE RATE only (not fringe).")
    print("  Fringe is paid flat for every hour worked.\n")

    print("  --- RATES (from DIR wage determination) ---")
    base_rate = get_dollar_input("  Base hourly rate: $")
    if base_rate <= 0:
        print("  Base rate is required.")
        return
    fringe_rate = get_dollar_input("  Fringe benefit rate (per hour): $")
    print_row("  Prevailing wage rate:", fmt(base_rate + fringe_rate))

    fringe_cash = get_yn_input("  Fringe paid as cash (taxable)? ")

    print("\n  --- HOURS (for the pay period or YTD) ---")
    print("  Enter total hours for the period you need.\n")
    regular = get_dollar_input("  Regular hours (straight time): ")
    ot_weekday = get_dollar_input("  Weekday OT hours (1.5x, over 8/day or 40/wk): ")
    saturday = get_dollar_input("  Saturday hours (1.5x): ")
    dt_weekday = get_dollar_input("  Weekday double-time hours (2x, over 12/day): ")
    sunday = get_dollar_input("  Sunday hours (2x): ")

    result = calculate_prevailing_wage_ot(
        base_rate=base_rate,
        fringe_rate=fringe_rate,
        regular_hours=regular,
        ot_hours=ot_weekday,
        dt_hours=dt_weekday,
        saturday_hours=saturday,
        sunday_hours=sunday,
        fringe_paid_as_cash=fringe_cash,
    )

    display_pw_results(result)
    return result


def pw_ot_quick(base_rate: float, fringe_rate: float,
                regular: float, ot: float, dt: float = 0.0,
                fringe_cash: bool = False):
    """Quick prevailing wage OT calc from CLI args."""
    result = calculate_prevailing_wage_ot(
        base_rate=base_rate,
        fringe_rate=fringe_rate,
        regular_hours=regular,
        ot_hours=ot,
        dt_hours=dt,
        fringe_paid_as_cash=fringe_cash,
    )
    display_pw_results(result)
    return result


def display_pw_results(r: dict):
    """Display prevailing wage OT breakdown."""
    print_section("RATES")
    print_row("Base rate:", fmt(r["base_rate"]))
    print_row("Fringe rate:", fmt(r["fringe_rate"]))
    print_row("Prevailing wage rate:", fmt(r["prevailing_wage_rate"]))

    print_section("HOURS")
    print_row("Regular (straight time):", f"{r['regular_hours']} hrs")
    if r["ot_hours"] > 0:
        parts = []
        if r["ot_hours_weekday"] > 0:
            parts.append(f"{r['ot_hours_weekday']} weekday")
        if r["ot_hours_saturday"] > 0:
            parts.append(f"{r['ot_hours_saturday']} Saturday")
        print_row("OT hours (1.5x):", f"{r['ot_hours']} hrs ({', '.join(parts)})")
    if r["dt_hours"] > 0:
        parts = []
        if r["dt_hours_weekday"] > 0:
            parts.append(f"{r['dt_hours_weekday']} weekday")
        if r["dt_hours_sunday"] > 0:
            parts.append(f"{r['dt_hours_sunday']} Sunday")
        print_row("DT hours (2x):", f"{r['dt_hours']} hrs ({', '.join(parts)})")
    print_row("Total hours:", f"{r['total_hours']} hrs")

    print_section("PAY BREAKDOWN")
    print_row("Regular pay:",
              f"{r['regular_hours']} hrs x {fmt(r['base_rate'])} = {fmt(r['regular_base_pay'])}")
    if r["ot_hours"] > 0:
        print_row("OT pay (1.5x base):",
                  f"{r['ot_hours']} hrs x {fmt(r['ot_base_rate'])} = {fmt(r['ot_base_pay'])}")
        print_row("  OT premium (extra 0.5x):", fmt(r["ot_premium_amount"]))
    if r["dt_hours"] > 0:
        print_row("DT pay (2x base):",
                  f"{r['dt_hours']} hrs x {fmt(r['dt_base_rate'])} = {fmt(r['dt_base_pay'])}")
        print_row("  DT premium (extra 1.0x):", fmt(r["dt_premium_amount"]))
    print(f"  {'-' * 45}")
    print_row("Total base wages:", fmt(r["total_base_pay"]))

    print_section("FRINGE BENEFITS")
    cash_note = " (TAXABLE - paid as cash)" if r["fringe_paid_as_cash"] else " (non-taxable benefits)"
    print_row("Fringe:",
              f"{r['total_hours']} hrs x {fmt(r['fringe_rate'])} = {fmt(r['total_fringe'])}{cash_note}")

    print_section("PREMIUM OT SUMMARY (for tax return)")
    print_row("Total premium OT amount:", fmt(r["total_premium_ot"]))
    print("  (This is the extra amount above straight-time")
    print("   due to 1.5x and 2x multipliers on your base rate)")

    print_section("TOTALS")
    print_row("Total base wages:", fmt(r["total_base_pay"]))
    print_row("Total fringe:", fmt(r["total_fringe"]))
    print_row("Gross compensation:", fmt(r["gross_compensation"]))
    print_row("Taxable wages (W-2):", fmt(r["taxable_wages"]))
    if not r["fringe_paid_as_cash"]:
        print("  (Fringe paid as benefits, not included in taxable wages)")
    print()


def show_history():
    """Display past calculation results."""
    results = list_results()
    if not results:
        print("\n  No saved calculations yet.")
        return

    print_section("CALCULATION HISTORY")
    for i, r in enumerate(results[:10]):  # Show last 10
        ts = r["timestamp"][:16].replace("T", " ")
        inputs = r.get("inputs", {})
        summary = r.get("result", {}).get("summary", {})
        income = inputs.get("gross_income", 0)
        status = inputs.get("filing_status", "single")
        take_home = summary.get("estimated_take_home", 0)
        rate = summary.get("overall_effective_rate", 0)
        print(f"  {i+1}. {ts} | {status.title()} | "
              f"Income: {fmt(income)} | Take-home: {fmt(take_home)} | Rate: {rate}%")
    print()


def check_resume() -> dict | None:
    """Check for saved draft and offer to resume."""
    draft = load_draft()
    if not draft:
        return None

    print(f"\n  Saved draft found:")
    print(f"    {format_draft_summary(draft)}")
    choice = input("\n  Resume? (y/n) [y]: ").strip().lower()
    if choice == "n":
        clear_draft()
        return None
    return draft["fields"]


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
    parser.add_argument("--pw", action="store_true",
                        help="Prevailing wage OT calculator (interactive)")
    parser.add_argument("--pw-quick", nargs=5, type=float,
                        metavar=("BASE", "FRINGE", "REG", "OT", "DT"),
                        help="Quick prevailing wage OT: base_rate fringe_rate reg_hrs ot_hrs dt_hrs")
    parser.add_argument("--fringe-cash", action="store_true",
                        help="With --pw-quick: fringe paid as taxable cash")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--import-adp", metavar="CSV_FILE",
                        help="Import pay data from ADP CSV export")
    parser.add_argument("--adp", action="store_true",
                        help="Guided entry from ADP pay stub")
    parser.add_argument("--profile", metavar="NAME",
                        help="Load a saved profile to pre-fill fields")
    parser.add_argument("--save-profile", metavar="NAME",
                        help="Save inputs as a named profile after calculation")
    parser.add_argument("--list-profiles", action="store_true",
                        help="List saved profiles")
    parser.add_argument("--history", action="store_true",
                        help="View past calculations")

    args = parser.parse_args()

    # History
    if args.history:
        show_history()
        return

    # List profiles
    if args.list_profiles:
        profiles = list_profiles()
        if profiles:
            print("\n  Saved profiles:")
            for p in profiles:
                print(f"    - {p}")
        else:
            print("\n  No saved profiles. Use --save-profile NAME after a calculation.")
        return

    # Prevailing wage OT (interactive)
    if args.pw:
        pw_ot_interactive()
        return

    # Prevailing wage OT (quick)
    if args.pw_quick:
        b, f, reg, ot, dt = args.pw_quick
        result = calculate_prevailing_wage_ot(
            base_rate=b, fringe_rate=f,
            regular_hours=reg, ot_hours=ot, dt_hours=dt,
            fringe_paid_as_cash=args.fringe_cash,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            display_pw_results(result)
        return

    # OT quick calc
    if args.ot:
        if args.json:
            result = calculate_overtime_pay(args.ot[0], args.ot[1], args.ot[2])
            print(json.dumps(result, indent=2))
        else:
            ot_calc(args.ot[0], args.ot[1], args.ot[2])
        return

    # Quick estimate
    if args.quick:
        if args.json:
            result = full_tax_summary(gross_income=args.quick,
                                      filing_status=args.status)
            print(json.dumps(result, indent=2, default=str))
        else:
            quick_estimate(args.quick, args.status)
        return

    # Build prefill from various sources
    prefill = {}

    # Load profile if specified
    if args.profile:
        profile_data = load_profile(args.profile)
        if profile_data:
            prefill.update(profile_data)
            prefill["_source"] = f"profile '{args.profile}'"
            print(f"\n  Loaded profile: {args.profile}")
        else:
            print(f"\n  Profile '{args.profile}' not found. Starting fresh.")

    # ADP CSV import
    if args.import_adp:
        adp_data = parse_adp_csv(args.import_adp)
        if "error" in adp_data:
            print(f"\n  ADP import error: {adp_data['error']}")
            return
        calc_fields = apply_adp_data(adp_data)
        prefill.update(calc_fields)
        prefill["_source"] = adp_data.get("_source", "ADP CSV")
        periods = adp_data.get("_pay_periods", 0)
        print(f"\n  Imported {periods} pay period(s) from ADP.")

    # ADP guided entry
    if args.adp:
        adp_data = guided_adp_entry()
        calc_fields = apply_adp_data(adp_data)
        prefill.update(calc_fields)
        prefill["_source"] = "ADP pay stub entry"

    # Check for saved draft (only if no other prefill source)
    if not prefill:
        resumed = check_resume()
        if resumed:
            prefill = resumed
            prefill["_source"] = "saved draft"

    # Run interactive with whatever prefill we have
    fields = run_interactive(prefill)

    # Save profile if requested
    if args.save_profile and fields:
        # Only save stable fields (not amounts that change each year)
        stable_fields = {
            k: v for k, v in fields.items()
            if k in ("filing_status", "is_self_employed", "hourly_rate", "regular_hours")
        }
        save_profile(args.save_profile, stable_fields)
        print(f"  Profile saved as '{args.save_profile}'")


if __name__ == "__main__":
    main()
