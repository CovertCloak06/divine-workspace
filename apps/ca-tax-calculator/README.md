# CA Tax Calculator

California tax return helper that calculates health insurance premium deductions, itemized deductions, overtime pay rates, and estimated federal + state taxes.

## Features

- **Overtime Pay** - CA labor law rates (1.5x and 2x)
- **Premium Deductions** - Health insurance (W-2 and self-employed)
- **Itemized Deductions** - Medical, mortgage, SALT ($10k cap), charitable
- **Federal Income Tax** - 2025 brackets (single & married)
- **CA State Income Tax** - 2025 brackets
- **Payroll Taxes** - Social Security, Medicare, CA SDI
- **Full Summary** - Total tax burden and estimated take-home

## Usage

```bash
# Interactive mode - walks through all inputs
python main.py

# Quick estimate for $85,000 income
python main.py --quick 85000

# Quick estimate, married filing jointly
python main.py --quick 120000 --status married

# Overtime calculation: $25/hr, 40 regular hrs, 10 OT hrs
python main.py --ot 25 40 10

# JSON output
python main.py --quick 85000 --json
```

## Example Output

```
==================================================
  TOTAL TAX SUMMARY
==================================================
  Gross income:                        $85,000.00
  Federal tax:                         $10,852.00
  CA state tax:                        $3,550.48
  Payroll taxes:                       $8,520.00
  ---------------------------------------------
  Total tax burden:                    $22,922.48
  Estimated take-home:                 $62,077.52
  Overall effective rate:              26.97%
```

## As a Library

```python
from ca_tax_calculator import full_tax_summary, calculate_overtime_pay

# Full tax summary
result = full_tax_summary(
    gross_income=85000,
    filing_status="single",
    health_premium=6000,
    is_self_employed=False,
)

# Just OT calculation
ot = calculate_overtime_pay(hourly_rate=25, overtime_hours=10)
```

## Tests

```bash
python tests/test_calculator.py
# or
pytest tests/
```

## Disclaimer

This calculator provides **estimates only**. Tax laws change frequently. Consult a qualified tax professional for your actual tax return.
