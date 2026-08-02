"""Generate a synthetic messy spreadsheet for end-to-end CLI testing.

Run: python sample_data/generate_sample.py
Creates: sample_data/messy_data.xlsx  and  sample_data/contacts.csv

All identifiers are fabricated — none are real. The files contain a mix of
clean structured data, cells with multiple values (comma-separated), and
intentional noise (order IDs that look like phone numbers, etc.).
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

# Allow running from the project root
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import openpyxl
from phi_scanner.recognizers.aadhaar import verhoeff_check_digit
from phi_scanner.recognizers.gstin import _gstin_check_digit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_aadhaar(prefix: str) -> str:
    return prefix + verhoeff_check_digit(prefix)


def make_gstin(prefix14: str) -> str:
    return prefix14 + _gstin_check_digit(prefix14)


# ---------------------------------------------------------------------------
# Synthetic data rows
# ---------------------------------------------------------------------------

PEOPLE = [
    {
        "employee_id": "EMP001",
        "name": "Priya Sharma",
        "aadhaar": make_aadhaar("23456789012"),
        "pan": "ABCPD1234E",
        "gstin": make_gstin("29ABCPD1234E1Z"),
        "mobile": "9876543210",
        "department": "Finance",
    },
    {
        "employee_id": "EMP002",
        "name": "Rajesh Kumar",
        "aadhaar": make_aadhaar("34567890123"),
        "pan": "XYZCA5678F",
        "gstin": "",
        "mobile": "+91 8765432109",
        "department": "Engineering",
    },
    {
        "employee_id": "EMP003",
        "name": "Aisha Begum",
        "aadhaar": f"{make_aadhaar('45678901234')[:4]} {make_aadhaar('45678901234')[4:8]} {make_aadhaar('45678901234')[8:]}",  # spaced
        "pan": "DEFHG2345K",
        "gstin": make_gstin("27DEFHG2345K1Z"),
        "mobile": "7654321098",
        "department": "HR",
    },
    {
        "employee_id": "EMP004",
        "name": "Suresh Pillai",
        "aadhaar": "",   # missing — tests recall
        "pan": "MNOFS6789L",
        "gstin": "",
        "mobile": "6543210987",
        "department": "Sales",
    },
    {
        "employee_id": "EMP005",
        "name": "Kavita Nair",
        "aadhaar": make_aadhaar("56789012345"),
        "pan": "",
        "gstin": make_gstin("33MNOFS6789L1Z"),
        "mobile": "9123456789",
        "department": "Legal",
    },
]

# Noise rows — should not produce HIGH-confidence findings
NOISE_ROWS = [
    {"employee_id": "N001", "name": "Order ref", "notes": "Ref: 1234567890123 (13 digits — not Aadhaar)"},
    {"employee_id": "N002", "name": "Amount", "notes": "Turnover: 5000000000 (10 digit amount)"},
    {"employee_id": "N003", "name": "Timestamp", "notes": "20261101120000"},
]


def write_xlsx(out: Path) -> None:
    wb = openpyxl.Workbook()
    ws_emp = wb.active
    ws_emp.title = "Employees"

    headers = list(PEOPLE[0].keys())
    ws_emp.append(headers)
    for p in PEOPLE:
        ws_emp.append([p[h] for h in headers])

    ws_noise = wb.create_sheet("Noise")
    ws_noise.append(["employee_id", "name", "notes"])
    for n in NOISE_ROWS:
        ws_noise.append([n["employee_id"], n["name"], n["notes"]])

    wb.save(out)
    print(f"Written: {out}")


def write_csv(out: Path) -> None:
    fieldnames = ["name", "mobile", "aadhaar_no", "pan_no"]
    rows = [
        {"name": p["name"], "mobile": p["mobile"],
         "aadhaar_no": p["aadhaar"], "pan_no": p["pan"]}
        for p in PEOPLE
    ]
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Written: {out}")


if __name__ == "__main__":
    sample_dir = Path(__file__).parent
    write_xlsx(sample_dir / "messy_data.xlsx")
    write_csv(sample_dir / "contacts.csv")
