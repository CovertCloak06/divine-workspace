"""
Phonescan Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import json
import time


# Create blueprint
phonescan_bp = Blueprint("phonescan", __name__)


@phonescan_bp.route("/phonescan", methods=["POST"])
def phonescan():
    try:
        data = request.get_json()
        number = data.get("number", "")

        if not number:
            return jsonify({"error": "No phone number provided"}), 400

        # Parse the phone number
        parsed = phonenumbers.parse(number, None)

        # Get information
        is_valid = phonenumbers.is_valid_number(parsed)
        country = geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "en")
        timezones = timezone.time_zones_for_number(parsed)
        number_type = phonenumbers.number_type(parsed)

        # Map number type to readable string
        type_map = {
            0: "Fixed Line",
            1: "Mobile",
            2: "Fixed Line or Mobile",
            3: "Toll Free",
            4: "Premium Rate",
            5: "Shared Cost",
            6: "VoIP",
            7: "Personal Number",
            8: "Pager",
            9: "UAN",
            10: "Voicemail",
            99: "Unknown",
        }

        result = {
            "number": number,
            "valid": is_valid,
            "country": country or "Unknown",
            "carrier": carrier_name or "Unknown",
            "timezones": list(timezones) if timezones else ["Unknown"],
            "type": type_map.get(number_type, "Unknown"),
            "international_format": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "e164_format": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            ),
            "summary": f"Phone Number Analysis: {number} ({country})",
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e), "number": number, "valid": False}), 400
