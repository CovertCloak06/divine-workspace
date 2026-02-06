"""ADP Pay Stub Import for CA Tax Calculator.

Parses exported pay data from ADP to auto-fill calculator fields.
Supports:
- ADP CSV export (from ADP portal "Download Pay Statement")
- Manual entry from ADP pay stub values (guided)

No ADP credentials are stored or transmitted. All parsing happens locally.
"""

import csv
import re
from pathlib import Path


# Common ADP CSV column headers (varies by employer setup)
ADP_COLUMN_MAP = {
    # Gross pay
    "gross pay": "gross_income",
    "gross earnings": "gross_income",
    "total gross": "gross_income",
    "total earnings": "gross_income",
    # Regular pay
    "regular": "regular_pay",
    "regular pay": "regular_pay",
    "regular earnings": "regular_pay",
    # Overtime
    "overtime": "overtime_pay",
    "ot pay": "overtime_pay",
    "overtime pay": "overtime_pay",
    # Hours
    "regular hours": "regular_hours",
    "reg hours": "regular_hours",
    "ot hours": "overtime_hours",
    "overtime hours": "overtime_hours",
    # Rate
    "rate": "hourly_rate",
    "regular rate": "hourly_rate",
    "hourly rate": "hourly_rate",
    "pay rate": "hourly_rate",
    # Deductions
    "federal tax": "federal_withheld",
    "fed tax": "federal_withheld",
    "federal income tax": "federal_withheld",
    "state tax": "state_withheld",
    "ca state tax": "state_withheld",
    "ca sit": "state_withheld",
    "social security": "ss_withheld",
    "oasdi": "ss_withheld",
    "medicare": "medicare_withheld",
    "ca sdi": "sdi_withheld",
    "sdi": "sdi_withheld",
    # Benefits
    "medical": "health_premium",
    "health": "health_premium",
    "dental": "dental_premium",
    "vision": "vision_premium",
    "medical employee": "health_premium",
    "medical ee": "health_premium",
}


def _clean_amount(value: str) -> float:
    """Parse dollar amount from various formats ($1,234.56 or 1234.56 or (123.45))."""
    if not value or not value.strip():
        return 0.0
    cleaned = value.strip().replace("$", "").replace(",", "")
    # Handle negative in parentheses: (123.45)
    if cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = "-" + cleaned[1:-1]
    try:
        return abs(float(cleaned))
    except ValueError:
        return 0.0


def parse_adp_csv(filepath: str) -> dict:
    """Parse an ADP CSV pay statement export.

    Returns dict with fields that can be used to pre-fill the calculator.
    """
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}
    if not path.suffix.lower() == ".csv":
        return {"error": f"Expected .csv file, got {path.suffix}"}

    result = {}
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return {"error": "CSV has no headers"}

            # Map columns
            col_mapping = {}
            for csv_col in reader.fieldnames:
                normalized = csv_col.strip().lower()
                if normalized in ADP_COLUMN_MAP:
                    col_mapping[csv_col] = ADP_COLUMN_MAP[normalized]

            # Read rows (may be multiple pay periods)
            rows = list(reader)
            if not rows:
                return {"error": "CSV has no data rows"}

            # Sum up YTD or all pay periods
            for row in rows:
                for csv_col, field_name in col_mapping.items():
                    val = _clean_amount(row.get(csv_col, ""))
                    if val > 0:
                        if field_name in result:
                            result[field_name] += val
                        else:
                            result[field_name] = val

            # Use latest rate/hours (not summed)
            last_row = rows[-1]
            for csv_col, field_name in col_mapping.items():
                if field_name in ("hourly_rate", "regular_hours", "overtime_hours"):
                    val = _clean_amount(last_row.get(csv_col, ""))
                    if val > 0:
                        result[field_name] = val

    except Exception as e:
        return {"error": f"Failed to parse CSV: {e}"}

    # Combine medical/dental/vision into total health premium
    health_total = sum(result.pop(k, 0) for k in ["health_premium", "dental_premium", "vision_premium"])
    if health_total > 0:
        result["health_premium"] = round(health_total, 2)

    # Round all values
    for k in result:
        if isinstance(result[k], float):
            result[k] = round(result[k], 2)

    result["_source"] = f"ADP import from {path.name}"
    result["_pay_periods"] = len(rows)
    return result


def guided_adp_entry() -> dict:
    """Walk the user through entering key values from their ADP pay stub.

    This is for when they don't have a CSV export but are looking at the
    ADP app or a PDF pay stub.
    """
    print("\n  ==========================================")
    print("  ADP PAY STUB ENTRY")
    print("  ==========================================")
    print("  Enter values from your ADP pay stub.")
    print("  Look at your most recent stub or YTD totals.")
    print("  Press Enter to skip any field.\n")

    def ask(prompt: str) -> float:
        raw = input(f"  {prompt}: $").strip().replace(",", "").replace("$", "")
        if not raw:
            return 0.0
        try:
            return abs(float(raw))
        except ValueError:
            return 0.0

    result = {}

    print("  --- EARNINGS (from 'Earnings' section) ---")
    result["gross_income"] = ask("YTD Gross Pay (or annual salary)")
    result["hourly_rate"] = ask("Hourly Rate (if hourly employee)")

    if result["hourly_rate"] > 0:
        print("\n  --- HOURS (from current pay period) ---")
        result["regular_hours"] = ask("Regular Hours this period")
        result["overtime_hours"] = ask("OT Hours this period")
        result["double_time_hours"] = ask("Double-Time Hours (if any)")

    print("\n  --- DEDUCTIONS (from 'Employee Deductions') ---")
    result["health_premium"] = ask("YTD Medical/Health Premium (employee portion)")
    dental = ask("YTD Dental Premium (if separate)")
    vision = ask("YTD Vision Premium (if separate)")
    if dental > 0 or vision > 0:
        result["health_premium"] = round(result.get("health_premium", 0) + dental + vision, 2)

    print("\n  --- TAXES WITHHELD (from 'Taxes' section) ---")
    print("  (These help verify your calculator results)")
    result["federal_withheld"] = ask("YTD Federal Tax Withheld")
    result["state_withheld"] = ask("YTD CA State Tax Withheld")

    # Clean out zeros
    result = {k: v for k, v in result.items() if v > 0}
    result["_source"] = "ADP manual entry"
    return result


def apply_adp_data(adp_data: dict) -> dict:
    """Convert ADP import data to calculator input fields."""
    calc_fields = {}

    if adp_data.get("gross_income"):
        calc_fields["gross_income"] = adp_data["gross_income"]
    if adp_data.get("hourly_rate"):
        calc_fields["hourly_rate"] = adp_data["hourly_rate"]
    if adp_data.get("regular_hours"):
        calc_fields["regular_hours"] = adp_data["regular_hours"]
    if adp_data.get("overtime_hours"):
        calc_fields["overtime_hours"] = adp_data["overtime_hours"]
    if adp_data.get("double_time_hours"):
        calc_fields["double_time_hours"] = adp_data["double_time_hours"]
    if adp_data.get("health_premium"):
        calc_fields["health_premium"] = adp_data["health_premium"]

    # Store withholding for comparison (not used in calculation, but shown after)
    if adp_data.get("federal_withheld"):
        calc_fields["_federal_withheld"] = adp_data["federal_withheld"]
    if adp_data.get("state_withheld"):
        calc_fields["_state_withheld"] = adp_data["state_withheld"]

    return calc_fields
