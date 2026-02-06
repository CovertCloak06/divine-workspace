"""
CA Tax Calculator - California Tax Return Helper

Calculates:
- Health insurance premium deductions
- Itemized deductions (medical, mortgage, SALT, charity)
- Overtime (OT) pay rate and tax withholding
- California state income tax brackets (2025)
- Federal income tax brackets (2025)
"""

# --- California State Tax Brackets (2025, Single Filer) ---
CA_TAX_BRACKETS_SINGLE = [
    (10_099, 0.01),
    (23_942, 0.02),
    (37_788, 0.04),
    (52_455, 0.06),
    (66_295, 0.08),
    (338_639, 0.093),
    (406_364, 0.103),
    (677_275, 0.113),
    (1_000_000, 0.123),
    (float("inf"), 0.133),
]

CA_TAX_BRACKETS_MARRIED = [
    (20_198, 0.01),
    (47_884, 0.02),
    (75_576, 0.04),
    (104_910, 0.06),
    (132_590, 0.08),
    (677_278, 0.093),
    (812_728, 0.103),
    (1_000_000, 0.113),
    (1_354_550, 0.123),
    (float("inf"), 0.133),
]

# --- Federal Tax Brackets (2025, Single Filer) ---
FEDERAL_TAX_BRACKETS_SINGLE = [
    (11_600, 0.10),
    (47_150, 0.12),
    (100_525, 0.22),
    (191_950, 0.24),
    (243_725, 0.32),
    (609_350, 0.35),
    (float("inf"), 0.37),
]

FEDERAL_TAX_BRACKETS_MARRIED = [
    (23_200, 0.10),
    (94_300, 0.12),
    (201_050, 0.22),
    (383_900, 0.24),
    (487_450, 0.32),
    (731_200, 0.35),
    (float("inf"), 0.37),
]

# --- Standard Deductions (2025) ---
STANDARD_DEDUCTION = {
    "single": 14_600,
    "married": 29_200,
    "head_of_household": 21_900,
}

# --- California Standard Deduction (2025) ---
CA_STANDARD_DEDUCTION = {
    "single": 5_540,
    "married": 11_080,
}

# --- FICA / Payroll ---
SOCIAL_SECURITY_RATE = 0.062
SOCIAL_SECURITY_WAGE_CAP = 168_600
MEDICARE_RATE = 0.0145
MEDICARE_SURTAX_RATE = 0.009  # on wages over $200k single / $250k married

# --- SDI (CA State Disability Insurance) ---
CA_SDI_RATE = 0.011


def calculate_overtime_pay(hourly_rate: float, regular_hours: float = 40.0,
                           overtime_hours: float = 0.0,
                           double_time_hours: float = 0.0) -> dict:
    """Calculate overtime pay and totals per California labor law.

    CA OT rules:
    - 1.5x for hours over 8/day or 40/week (up to 12 hrs/day)
    - 2.0x for hours over 12/day or any hours on 7th consecutive day after 8 hrs
    """
    regular_pay = hourly_rate * regular_hours
    ot_rate = hourly_rate * 1.5
    ot_pay = ot_rate * overtime_hours
    dt_rate = hourly_rate * 2.0
    dt_pay = dt_rate * double_time_hours
    gross_pay = regular_pay + ot_pay + dt_pay

    return {
        "hourly_rate": hourly_rate,
        "regular_hours": regular_hours,
        "regular_pay": round(regular_pay, 2),
        "ot_rate": round(ot_rate, 2),
        "overtime_hours": overtime_hours,
        "overtime_pay": round(ot_pay, 2),
        "double_time_rate": round(dt_rate, 2),
        "double_time_hours": double_time_hours,
        "double_time_pay": round(dt_pay, 2),
        "gross_pay": round(gross_pay, 2),
    }


def calculate_premium_deduction(annual_premium: float,
                                employer_contribution: float = 0.0,
                                is_self_employed: bool = False) -> dict:
    """Calculate health insurance premium deduction.

    - W-2 employees: premiums paid pre-tax via employer aren't deductible again.
      Post-tax premiums count toward medical expense itemized deduction (>7.5% AGI).
    - Self-employed: 100% deductible as adjustment to income (line 17, Schedule 1).
    """
    out_of_pocket = annual_premium - employer_contribution

    if is_self_employed:
        return {
            "annual_premium": annual_premium,
            "employer_contribution": employer_contribution,
            "out_of_pocket": round(out_of_pocket, 2),
            "deduction_type": "Self-employed health insurance deduction (Schedule 1, Line 17)",
            "deductible_amount": round(out_of_pocket, 2),
            "note": "Deducted as adjustment to gross income (above the line). "
                    "Cannot exceed net self-employment income.",
        }
    else:
        return {
            "annual_premium": annual_premium,
            "employer_contribution": employer_contribution,
            "out_of_pocket": round(out_of_pocket, 2),
            "deduction_type": "Medical expense itemized deduction (Schedule A)",
            "deductible_amount": round(out_of_pocket, 2),
            "note": "Only the amount exceeding 7.5% of AGI is deductible. "
                    "Pre-tax premiums (paid via employer plan) are already excluded from income.",
        }


def calculate_itemized_deductions(medical_expenses: float = 0.0,
                                  agi: float = 0.0,
                                  mortgage_interest: float = 0.0,
                                  state_local_taxes: float = 0.0,
                                  charitable_donations: float = 0.0,
                                  other_deductions: float = 0.0) -> dict:
    """Calculate itemized deductions vs standard deduction."""
    # Medical: only amount exceeding 7.5% of AGI
    medical_threshold = agi * 0.075
    medical_deductible = max(0, medical_expenses - medical_threshold)

    # SALT cap: $10,000 ($5,000 if married filing separately)
    salt_deductible = min(state_local_taxes, 10_000)

    total_itemized = (medical_deductible + mortgage_interest +
                      salt_deductible + charitable_donations + other_deductions)

    return {
        "medical_expenses": medical_expenses,
        "medical_threshold_7_5_pct": round(medical_threshold, 2),
        "medical_deductible": round(medical_deductible, 2),
        "mortgage_interest": mortgage_interest,
        "state_local_taxes_paid": state_local_taxes,
        "salt_deductible_after_cap": salt_deductible,
        "charitable_donations": charitable_donations,
        "other_deductions": other_deductions,
        "total_itemized": round(total_itemized, 2),
    }


def _calculate_bracket_tax(taxable_income: float, brackets: list) -> float:
    """Calculate tax owed using progressive brackets."""
    tax = 0.0
    prev_limit = 0
    for limit, rate in brackets:
        if taxable_income <= 0:
            break
        taxable_in_bracket = min(taxable_income, limit - prev_limit)
        tax += taxable_in_bracket * rate
        taxable_income -= taxable_in_bracket
        prev_limit = limit
    return round(tax, 2)


def calculate_federal_tax(gross_income: float, deductions: float,
                          filing_status: str = "single") -> dict:
    """Calculate federal income tax."""
    taxable_income = max(0, gross_income - deductions)
    brackets = (FEDERAL_TAX_BRACKETS_MARRIED if filing_status == "married"
                else FEDERAL_TAX_BRACKETS_SINGLE)
    tax = _calculate_bracket_tax(taxable_income, brackets)
    effective_rate = (tax / gross_income * 100) if gross_income > 0 else 0

    return {
        "gross_income": gross_income,
        "deductions": deductions,
        "taxable_income": round(taxable_income, 2),
        "federal_tax": tax,
        "effective_rate": round(effective_rate, 2),
    }


def calculate_ca_state_tax(gross_income: float, deductions: float,
                           filing_status: str = "single") -> dict:
    """Calculate California state income tax."""
    taxable_income = max(0, gross_income - deductions)
    brackets = (CA_TAX_BRACKETS_MARRIED if filing_status == "married"
                else CA_TAX_BRACKETS_SINGLE)
    tax = _calculate_bracket_tax(taxable_income, brackets)
    effective_rate = (tax / gross_income * 100) if gross_income > 0 else 0

    return {
        "gross_income": gross_income,
        "ca_deductions": deductions,
        "ca_taxable_income": round(taxable_income, 2),
        "ca_state_tax": tax,
        "ca_effective_rate": round(effective_rate, 2),
    }


def calculate_payroll_taxes(gross_income: float,
                            filing_status: str = "single") -> dict:
    """Calculate FICA (Social Security + Medicare) and CA SDI."""
    ss_taxable = min(gross_income, SOCIAL_SECURITY_WAGE_CAP)
    social_security = ss_taxable * SOCIAL_SECURITY_RATE

    medicare = gross_income * MEDICARE_RATE
    surtax_threshold = 250_000 if filing_status == "married" else 200_000
    medicare_surtax = max(0, (gross_income - surtax_threshold)) * MEDICARE_SURTAX_RATE

    ca_sdi = gross_income * CA_SDI_RATE

    total = social_security + medicare + medicare_surtax + ca_sdi

    return {
        "social_security": round(social_security, 2),
        "medicare": round(medicare, 2),
        "medicare_surtax": round(medicare_surtax, 2),
        "ca_sdi": round(ca_sdi, 2),
        "total_payroll_taxes": round(total, 2),
    }


def full_tax_summary(gross_income: float,
                     filing_status: str = "single",
                     health_premium: float = 0.0,
                     employer_health_contribution: float = 0.0,
                     is_self_employed: bool = False,
                     medical_expenses: float = 0.0,
                     mortgage_interest: float = 0.0,
                     state_local_taxes: float = 0.0,
                     charitable_donations: float = 0.0,
                     hourly_rate: float = 0.0,
                     regular_hours: float = 0.0,
                     overtime_hours: float = 0.0,
                     double_time_hours: float = 0.0) -> dict:
    """Generate a complete CA tax return summary."""
    result = {}

    # 1. Overtime breakdown (if applicable)
    if hourly_rate > 0:
        result["overtime"] = calculate_overtime_pay(
            hourly_rate, regular_hours, overtime_hours, double_time_hours
        )

    # 2. Premium deduction
    if health_premium > 0:
        result["premium_deduction"] = calculate_premium_deduction(
            health_premium, employer_health_contribution, is_self_employed
        )

    # 3. Determine deductions
    se_health_deduction = 0.0
    if is_self_employed and health_premium > 0:
        se_health_deduction = health_premium - employer_health_contribution

    agi = gross_income - se_health_deduction

    itemized = calculate_itemized_deductions(
        medical_expenses=medical_expenses,
        agi=agi,
        mortgage_interest=mortgage_interest,
        state_local_taxes=state_local_taxes,
        charitable_donations=charitable_donations,
    )
    result["itemized_deductions"] = itemized

    std_ded = STANDARD_DEDUCTION.get(filing_status, STANDARD_DEDUCTION["single"])
    use_itemized = itemized["total_itemized"] > std_ded
    federal_deduction = itemized["total_itemized"] if use_itemized else std_ded

    result["deduction_choice"] = {
        "standard_deduction": std_ded,
        "itemized_total": itemized["total_itemized"],
        "using": "itemized" if use_itemized else "standard",
        "federal_deduction_amount": federal_deduction,
    }

    # 4. Federal tax
    result["federal"] = calculate_federal_tax(
        agi, federal_deduction + se_health_deduction, filing_status
    )

    # 5. California state tax
    ca_std = CA_STANDARD_DEDUCTION.get(filing_status, CA_STANDARD_DEDUCTION["single"])
    ca_deduction = max(itemized["total_itemized"], ca_std)
    result["california"] = calculate_ca_state_tax(agi, ca_deduction, filing_status)

    # 6. Payroll taxes
    result["payroll"] = calculate_payroll_taxes(gross_income, filing_status)

    # 7. Total tax burden
    total_tax = (result["federal"]["federal_tax"] +
                 result["california"]["ca_state_tax"] +
                 result["payroll"]["total_payroll_taxes"])
    take_home = gross_income - total_tax
    overall_rate = (total_tax / gross_income * 100) if gross_income > 0 else 0

    result["summary"] = {
        "gross_income": gross_income,
        "total_federal_tax": result["federal"]["federal_tax"],
        "total_ca_state_tax": result["california"]["ca_state_tax"],
        "total_payroll_taxes": result["payroll"]["total_payroll_taxes"],
        "total_tax_burden": round(total_tax, 2),
        "estimated_take_home": round(take_home, 2),
        "overall_effective_rate": round(overall_rate, 2),
    }

    return result
