import os
from typing import Dict, List

# Telegram Bot token
BOT_TOKEN = os.getenv("BOT_TOKEN", "8554133163:AAHpfU7P23xdx_BfeZrMC7S_uKVlNEUyOCM")

# Mongo
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb+srv://aztech:ayazahmed1122@cluster0.mhuaw3q.mongodb.net/aztechtgstore_db?retryWrites=true&w=majority",
)
DB_NAME = os.getenv("DB_NAME", "aztechtgstore_db")

# Admin Telegram user IDs (comma-separated)
ADMIN_USER_IDS: List[int] = [
    int(x)
    for x in os.getenv("ADMIN_USER_IDS", "6670166083").split(",")
    if x.strip().isdigit()
]

# Start screen image
START_IMAGE = "https://i.postimg.cc/XqXy0kTF/start.png"

# Support bot username (without @)
SUPPORT_USERNAME = os.getenv("SUPPORT_USERNAME", "AzTechDeveloper")

# Channel join requirement
CHANNEL_USERNAME = os.getenv("CHANNEL_USERNAME", "AzTechsHub")  # without @

# Report channel (bot must be admin there) - using channel ID for private channel
REPORT_CHANNEL_ID = int(os.getenv("REPORT_CHANNEL_ID", "-1003245912929"))

# Fixed Telegram API credentials used for adding accounts (admin flow)
TELEGRAM_API_ID = int(os.getenv("TELEGRAM_API_ID", "21425385"))
TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "b9d9201c2c03a56a397cad35b3991857")


# INR payment (UPI) - single QR option
INR_QRS: Dict[str, dict] = {
    "qr": {
        "label": "QR",
        "payee_name": "MOHAMMED AYAZ AHMED",
        "upi_id": "aztech7@axl",
        "notes": "REGARDS :- @AzTechDeveloper\n\nCHECK USERNAME BEFORE DEAL",
        "image_url": "https://i.postimg.cc/zBGkVWsH/inr.jpg",
    }
}

# Backwards compatibility (some code may still reference INR_PAYMENT)
INR_PAYMENT: dict = INR_QRS["qr"]