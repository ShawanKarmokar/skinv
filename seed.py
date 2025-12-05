# seed.py
from db import *

init_db()

# Add demo users if missing.  Use a temporary connection then close it.
conn = get_conn()
c = conn.cursor()
users = [
    ("Shawan", "01632", "superadmin"),
    ("ATN", "1230", "superadmin"),
    ("admin", "1234", "admin"),
    ("user", "1234", "user"),
]
for u, p, r in users:
    try:
        insert_user(u, p, r)
    except Exception:
        pass
conn.close()

# Add a demo item
try:
    insert_item(
        "superadmin",
        item_code="PC01",
        name="Office Desktop",
        product_id="HP-600G3",
        serial_number=None,
        status="In Stock",
        deployed_to="",
        ip_address="192.168.0.11",
        item_type="Desktop",
        unit=1,
        unit_price=45000,
        purchase_date="2024-06-12",
        invoice_no="INV-123",
        vendor_name="TechVendor",
        warranty_left="1 Year",
        approved=1,
    )
except Exception:
    # ignore errors such as locked DB or duplicate row
    pass

print("Seed complete.")
