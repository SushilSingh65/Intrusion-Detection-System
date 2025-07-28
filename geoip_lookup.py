# geoip_lookup.py
import requests

def get_geo_info(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        if "error" in data:
            return None

        return {
            "ip": ip,
            "country": data.get("country_name", "Unknown"),
            "region": data.get("region", "Unknown"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown")
        }
    except Exception as e:
        return None
