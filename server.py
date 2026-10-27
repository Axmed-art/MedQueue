"""Local MedQueue server and SQLite API."""

from __future__ import annotations

import json
import hashlib
import hmac
import mimetypes
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import parse_qs, unquote, urlsplit


# Пути заданы относительно этого файла, поэтому сервер можно запускать из любой папки.
ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "MedQueue"
DATA_ROOT = Path(os.environ.get("MEDQUEUE_DATA_DIR", str(ROOT))).expanduser()
DEFAULT_UPLOAD_ROOT = DATA_ROOT / "uploads" if os.environ.get("MEDQUEUE_DATA_DIR") else WEB_ROOT / "uploads"
UPLOAD_ROOT = Path(os.environ.get("MEDQUEUE_UPLOAD_DIR", str(DEFAULT_UPLOAD_ROOT))).expanduser()
DATABASE = Path(os.environ.get("MEDQUEUE_DATABASE_PATH", str(DATA_ROOT / "medqueue.db"))).expanduser()
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
SESSION_COOKIE = "medqueue_session"
SESSION_DAYS = 14
RESEND_API_URL = "https://api.resend.com/emails"


def send_email(to: str | None, subject: str, text: str) -> None:
    """Send a transactional email when Resend is configured; email failures are non-fatal."""
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    sender = os.environ.get("RESEND_FROM", "").strip()
    if not to or not to.strip():
        return
    if not api_key or not sender:
        print("Email notification skipped: set RESEND_API_KEY and RESEND_FROM to enable it.")
        return

    try:
        payload = json.dumps({"from": sender, "to": [to], "subject": subject, "text": text}).encode("utf-8")
        request = Request(
            RESEND_API_URL,
            data=payload,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=8) as response:
            if response.status >= 300:
                print(f"Email notification failed: Resend returned HTTP {response.status}.")
            else:
                print("Email notification accepted by Resend.")
    except HTTPError as error:
        try:
            details = json.loads(error.read().decode("utf-8"))
            error_name = str(details.get("name", ""))
            message = str(details.get("message", ""))
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            error_name, message = "", ""
        message = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[email]", message)
        message = message.replace(api_key, "[redacted]")[:300]
        reason = f", {error_name}: {message}" if error_name or message else ""
        print(f"Email notification failed (HTTP {error.code}{reason}).", flush=True)
    except Exception as error:
        print(f"Email notification failed ({type(error).__name__}).", flush=True)


def appointment_email_details(
    appointment_id: int,
    clinic_name: str,
    service: str,
    appointment_date: str,
    appointment_time: str,
    doctor_name: str = "",
    price: int | None = None,
    clinic_address: str = "",
) -> str:
    readable_date = datetime.strptime(appointment_date, "%Y-%m-%d").strftime("%d.%m.%Y")
    lines = [
        f"Номер записи: MQ-{appointment_id:05d}",
        f"Клиника: {clinic_name}",
    ]
    if clinic_address:
        lines.append(f"Адрес: {clinic_address}")
    lines.extend((f"Услуга: {service}", f"Дата: {readable_date}", f"Время: {appointment_time}"))
    if doctor_name:
        lines.append(f"Врач: {doctor_name}")
    if price is not None:
        lines.append(f"Стоимость: {price:,} ₸".replace(",", " "))
    return "\n".join(lines)


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def password_digest(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return salt.hex(), digest.hex()


def digest_session(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def auth_token(account_id: int, purpose: str, hours: int = 24) -> str:
    token = secrets.token_urlsafe(32)
    with connect_db() as connection:
        connection.execute("DELETE FROM auth_tokens WHERE account_id=? AND purpose=?", (account_id, purpose))
        connection.execute("INSERT INTO auth_tokens VALUES (?,?,?,?)", (
            digest_session(token), account_id, purpose,
            (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(),
        ))
    return token


def public_url(handler: BaseHTTPRequestHandler, path: str) -> str:
    base = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not base:
        scheme = "https" if handler.headers.get("X-Forwarded-Proto", "").lower() == "https" else "http"
        base = f"{scheme}://{handler.headers.get('Host', 'localhost')}"
    return f"{base}/{path.lstrip('/')}"


# Открываем отдельное соединение для каждого запроса и всегда закрываем его после ответа.
@contextmanager
def connect_db() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE, timeout=10)
    # Именованные поля удобнее использовать при подготовке JSON-ответов.
    connection.row_factory = sqlite3.Row
    # Включаем проверку внешнего ключа appointments.slot_id -> slots.id.
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


# Создаём таблицы при запуске и добавляем поля для существующей базы.
def initialize_database() -> None:
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as connection:
        connection.executescript(
            """
            -- Свободные даты, услуги и цены, которые администратор публикует для записи.
            CREATE TABLE IF NOT EXISTS slots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                clinic_name TEXT NOT NULL,
                service TEXT NOT NULL,
                appointment_date TEXT NOT NULL,
                appointment_time TEXT NOT NULL,
                price INTEGER NOT NULL CHECK (price > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (clinic_name, appointment_date, appointment_time)
            );

            -- Частичный уникальный индекс ниже резервирует слот только для активной записи.
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slot_id INTEGER NOT NULL REFERENCES slots(id) ON DELETE RESTRICT,
                patient_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('pending','confirmed','cancelled','completed')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                phone TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('patient', 'clinic', 'admin')),
                clinic_name TEXT,
                clinic_address TEXT,
                latitude REAL,
                longitude REAL,
                clinic_status TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS doctors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                clinic_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                specialty TEXT NOT NULL,
                experience INTEGER NOT NULL DEFAULT 0 CHECK (experience BETWEEN 0 AND 60),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (clinic_id, name)
            );
            CREATE TABLE IF NOT EXISTS clinic_photos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                clinic_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS favorites (
                patient_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                clinic_name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (patient_id, clinic_name)
            );
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token_hash TEXT PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                purpose TEXT NOT NULL CHECK (purpose IN ('verify_email','reset_password')),
                expires_at TEXT NOT NULL
            );
            """
        )

        account_columns = {row["name"] for row in connection.execute("PRAGMA table_info(accounts)")}
        if "email_verified" not in account_columns:
            connection.execute("ALTER TABLE accounts ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
        if "latitude" not in account_columns:
            connection.execute("ALTER TABLE accounts ADD COLUMN latitude REAL")
        if "longitude" not in account_columns:
            connection.execute("ALTER TABLE accounts ADD COLUMN longitude REAL")
        # Email verification is optional; existing accounts must remain usable too.
        connection.execute("UPDATE accounts SET email_verified=1 WHERE email_verified=0")

        slot_columns = {row["name"] for row in connection.execute("PRAGMA table_info(slots)")}
        if "owner_user_id" not in slot_columns:
            connection.execute("ALTER TABLE slots ADD COLUMN owner_user_id INTEGER REFERENCES accounts(id)")
        if "doctor_id" not in slot_columns:
            connection.execute("ALTER TABLE slots ADD COLUMN doctor_id INTEGER REFERENCES doctors(id) ON DELETE SET NULL")
        if "doctor_name" not in slot_columns:
            connection.execute("ALTER TABLE slots ADD COLUMN doctor_name TEXT NOT NULL DEFAULT ''")
        if "doctor_specialty" not in slot_columns:
            connection.execute("ALTER TABLE slots ADD COLUMN doctor_specialty TEXT NOT NULL DEFAULT ''")
        appointment_columns = {row["name"] for row in connection.execute("PRAGMA table_info(appointments)")}
        if "patient_id" not in appointment_columns:
            connection.execute("ALTER TABLE appointments ADD COLUMN patient_id INTEGER REFERENCES accounts(id)")
        if "status" not in appointment_columns:
            # Replace the legacy UNIQUE(slot_id) table so cancelled times can be booked again.
            connection.execute("ALTER TABLE appointments RENAME TO appointments_legacy")
            connection.execute("""CREATE TABLE appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slot_id INTEGER NOT NULL REFERENCES slots(id) ON DELETE RESTRICT,
                patient_name TEXT NOT NULL, phone TEXT NOT NULL,
                patient_id INTEGER REFERENCES accounts(id),
                status TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('pending','confirmed','cancelled','completed')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")
            connection.execute("""INSERT INTO appointments (id,slot_id,patient_name,phone,patient_id,created_at)
                SELECT id,slot_id,patient_name,phone,patient_id,created_at FROM appointments_legacy""")
            connection.execute("DROP TABLE appointments_legacy")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_active_appointment_per_slot ON appointments(slot_id) WHERE status IN ('pending','confirmed')")
        connection.execute("""CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_id INTEGER NOT NULL UNIQUE REFERENCES appointments(id) ON DELETE CASCADE,
            patient_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            clinic_name TEXT NOT NULL,
            rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
            comment TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        # Переименовываем старую демо-услугу, чтобы в каталоге везде было одно название.
        connection.execute(
            "UPDATE slots SET service='Приём при острой боли' WHERE service='Острая боль'"
        )

        admin_email = os.environ.get("SITE_ADMIN_EMAIL", "").strip().lower()
        admin_password = os.environ.get("SITE_ADMIN_PASSWORD", "")
        hosted = any(os.environ.get(key) for key in ("RENDER", "RENDER_EXTERNAL_URL", "RENDER_SERVICE_ID"))
        local_demo_admin = not hosted
        if local_demo_admin:
            admin_email = admin_email or "admin@medqueue.local"
            admin_password = admin_password or "MedQueue123!"
        if admin_email and admin_password:
            salt, digest = password_digest(admin_password)
            connection.execute(
                """INSERT INTO accounts (name,email,phone,password_salt,password_hash,role)
                   VALUES (?, ?, '', ?, ?, 'admin')
                   ON CONFLICT(email) DO UPDATE SET
                     name=excluded.name, password_salt=excluded.password_salt,
                     password_hash=excluded.password_hash, role='admin',
                     clinic_name=NULL, clinic_address=NULL, clinic_status=NULL""",
                ("Администратор MedQueue", admin_email, salt, digest),
            )
        elif hosted:
            print("ВНИМАНИЕ: задайте SITE_ADMIN_EMAIL и SITE_ADMIN_PASSWORD в Render → Environment, чтобы включить панель владельца.")


# Преобразуем строку SQLite в JSON-объект для страниц сайта.
def slot_record(row: sqlite3.Row, booked: bool = False) -> dict:
    return {
        "id": row["id"],
        "clinic_name": row["clinic_name"],
        "service": row["service"],
        "date": row["appointment_date"],
        "time": row["appointment_time"],
        "price": row["price"],
        "doctor_id": row["doctor_id"] if "doctor_id" in row.keys() else None,
        "doctor_name": row["doctor_name"] if "doctor_name" in row.keys() else "",
        "doctor_specialty": row["doctor_specialty"] if "doctor_specialty" in row.keys() else "",
        "booked": booked,
    }


class MedQueueHandler(BaseHTTPRequestHandler):
    server_version = "MedQueue/1.0"

    # Короткий журнал помогает видеть запросы сайта к серверу в окне запуска.
    def log_message(self, format: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")

    # Отправляем единый JSON-ответ, который читают JavaScript-страницы.
    def send_json(self, status: int, payload: dict | list, session: tuple[str, int] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # API-ответы не кэшируются: состояние слота меняется после каждой записи.
        self.send_header("Cache-Control", "no-store")
        if session:
            self.set_session_cookie(*session)
        self.end_headers()
        self.wfile.write(body)

    # Читаем JSON из POST-запроса и ограничиваем его размер.
    def read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 16_384:
                raise ValueError("Тело запроса пустое или слишком большое")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Ожидался JSON-объект")
            return payload
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("Некорректные данные запроса") from error

    def current_account(self) -> sqlite3.Row | None:
        cookie = self.headers.get("Cookie", "")
        token = next((part.strip().split("=", 1)[1] for part in cookie.split(";")
                      if part.strip().startswith(f"{SESSION_COOKIE}=")), "")
        if not token:
            return None
        with connect_db() as connection:
            return connection.execute(
                """SELECT a.*, s.token_hash FROM sessions s JOIN accounts a ON a.id=s.account_id
                   WHERE s.token_hash=? AND s.expires_at>?""",
                (digest_session(token), datetime.now(timezone.utc).isoformat()),
            ).fetchone()

    def require_account(self, role: str | None = None, approved_clinic: bool = False) -> sqlite3.Row:
        account = self.current_account()
        if account is None:
            raise ApiError(401, "Войдите в аккаунт, чтобы продолжить")
        if role and account["role"] != role:
            raise ApiError(403, "У этого аккаунта нет доступа к разделу")
        if approved_clinic and account["clinic_status"] != "approved":
            raise ApiError(403, "Расписание откроется после одобрения клиники")
        return account

    def set_session_cookie(self, token: str, max_age: int) -> None:
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE}={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age={max_age}{secure}",
        )

    @staticmethod
    def account_record(account: sqlite3.Row) -> dict:
        return {
            "id": account["id"], "name": account["name"], "email": account["email"],
            "phone": account["phone"], "role": account["role"],
            "clinic_name": account["clinic_name"], "clinic_address": account["clinic_address"],
            "latitude": account["latitude"], "longitude": account["longitude"],
            "clinic_status": account["clinic_status"], "email_verified": bool(account["email_verified"]),
        }

    def send_error_json(self, error: ApiError) -> None:
        self.send_json(error.status, {"error": error.message})

    def make_session(self, account_id: int) -> tuple[str, int]:
        token = secrets.token_urlsafe(32)
        max_age = SESSION_DAYS * 24 * 60 * 60
        expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
        with connect_db() as connection:
            connection.execute(
                "INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?, ?, ?)",
                (digest_session(token), account_id, expires),
            )
        return token, max_age

    def register_account(self) -> None:
        try:
            data = self.read_json()
        except ValueError as error:
            raise ApiError(400, str(error)) from error
        role = str(data.get("role", "patient")).strip()
        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        phone = str(data.get("phone", "")).strip()
        password = str(data.get("password", ""))
        clinic_name = str(data.get("clinic_name", "")).strip()
        clinic_address = str(data.get("clinic_address", "")).strip()
        if role not in {"patient", "clinic"}:
            raise ApiError(400, "Выберите тип аккаунта")
        if len(name) < 2 or len(name) > 100:
            raise ApiError(400, "Введите имя длиной от 2 до 100 символов")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
            raise ApiError(400, "Введите корректную почту")
        if len(re.sub(r"\D", "", phone)) < 7 or len(phone) > 30:
            raise ApiError(400, "Введите корректный телефон")
        if len(password) < 8 or len(password) > 256:
            raise ApiError(400, "Пароль должен содержать от 8 до 256 символов")
        if role == "clinic" and (len(clinic_name) < 2 or len(clinic_name) > 160 or len(clinic_address) < 3):
            raise ApiError(400, "Заполните название и адрес клиники")
        salt, digest = password_digest(password)
        try:
            with connect_db() as connection:
                cursor = connection.execute(
                    """INSERT INTO accounts
                       (name,email,phone,password_salt,password_hash,role,clinic_name,clinic_address,clinic_status,email_verified)
                       VALUES (?,?,?,?,?,?,?,?,?,1)""",
                    (name, email, phone, salt, digest, role, clinic_name or None,
                     clinic_address or None, "pending" if role == "clinic" else None),
                )
                account_id = cursor.lastrowid
                account = connection.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        except sqlite3.IntegrityError as error:
            raise ApiError(409, "Аккаунт с такой почтой уже существует") from error
        self.send_json(201, self.account_record(account), self.make_session(account_id))

    def login(self) -> None:
        try:
            data = self.read_json()
        except ValueError as error:
            raise ApiError(400, str(error)) from error
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        with connect_db() as connection:
            account = connection.execute("SELECT * FROM accounts WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        if account is None:
            raise ApiError(401, "Неверная почта или пароль")
        _, digest = password_digest(password, bytes.fromhex(account["password_salt"]))
        if not hmac.compare_digest(digest, account["password_hash"]):
            raise ApiError(401, "Неверная почта или пароль")
        self.send_json(200, self.account_record(account), self.make_session(account["id"]))

    def request_verification(self) -> None:
        try:
            email = str(self.read_json().get("email", "")).strip().lower()
        except ValueError as error:
            raise ApiError(400, str(error)) from error
        with connect_db() as connection:
            account = connection.execute("SELECT id,name,email,email_verified FROM accounts WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        if account and not account["email_verified"]:
            token = auth_token(account["id"], "verify_email")
            link = public_url(self, f"api/auth/verify-email?token={token}")
            send_email(account["email"], "Подтвердите почту — MedQueue", f"Здравствуйте, {account['name']}!\n\nПодтвердите почту:\n{link}\n\nСсылка действует 24 часа.")
        self.send_json(200, {"sent": True})

    def verify_email(self, token: str) -> None:
        with connect_db() as connection:
            row = connection.execute("SELECT account_id FROM auth_tokens WHERE token_hash=? AND purpose='verify_email' AND expires_at>?", (digest_session(token), datetime.now(timezone.utc).isoformat())).fetchone()
            if row is None:
                raise ApiError(400, "Ссылка недействительна или устарела. Запросите новое письмо.")
            connection.execute("UPDATE accounts SET email_verified=1 WHERE id=?", (row["account_id"],))
            connection.execute("DELETE FROM auth_tokens WHERE account_id=? AND purpose='verify_email'", (row["account_id"],))
        self.send_response(302); self.send_header("Location", "/account.html?verified=1"); self.end_headers()

    def request_password_reset(self) -> None:
        try:
            email = str(self.read_json().get("email", "")).strip().lower()
        except ValueError as error:
            raise ApiError(400, str(error)) from error
        with connect_db() as connection:
            account = connection.execute("SELECT id,name,email FROM accounts WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        if account:
            print("Password reset: matching account found; requesting email delivery.")
            token = auth_token(account["id"], "reset_password", 1)
            link = public_url(self, f"account.html?reset={token}")
            send_email(account["email"], "Сброс пароля — MedQueue", f"Здравствуйте, {account['name']}!\n\nЧтобы задать новый пароль, откройте ссылку:\n{link}\n\nСсылка действует 1 час. Если вы не запрашивали сброс, проигнорируйте письмо.")
        else:
            print("Password reset: no matching account; no email was sent.")
        self.send_json(200, {"sent": True})

    def reset_password(self) -> None:
        try:
            data = self.read_json(); token = str(data.get("token", "")); password = str(data.get("password", ""))
        except ValueError as error:
            raise ApiError(400, str(error)) from error
        if len(password) < 8 or len(password) > 256:
            raise ApiError(400, "Пароль должен содержать от 8 до 256 символов")
        with connect_db() as connection:
            row = connection.execute("SELECT account_id FROM auth_tokens WHERE token_hash=? AND purpose='reset_password' AND expires_at>?", (digest_session(token), datetime.now(timezone.utc).isoformat())).fetchone()
            if row is None: raise ApiError(400, "Ссылка недействительна или устарела. Запросите сброс пароля снова.")
            salt, digest = password_digest(password)
            connection.execute("UPDATE accounts SET password_salt=?,password_hash=? WHERE id=?", (salt,digest,row["account_id"]))
            connection.execute("DELETE FROM sessions WHERE account_id=?", (row["account_id"],))
            connection.execute("DELETE FROM auth_tokens WHERE account_id=? AND purpose='reset_password'", (row["account_id"],))
        self.send_json(200, {"reset": True})

    def logout(self) -> None:
        account = self.current_account()
        if account:
            with connect_db() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (account["token_hash"],))
        self.send_json(200, {"logged_out": True}, ("", 0))

    @staticmethod
    def appointment_record(row: sqlite3.Row) -> dict:
        status = row["status"]
        appointment_at = datetime.combine(date.fromisoformat(row["appointment_date"]),
                                          datetime.strptime(row["appointment_time"], "%H:%M").time())
        if status == "confirmed" and appointment_at <= datetime.now():
            status = "completed"
        return {
            "id": row["id"], "patient_name": row["patient_name"], "phone": row["phone"],
            "created_at": row["created_at"], "status": status,
            "has_review": bool(row["has_review"]) if "has_review" in row.keys() else False,
            "slot": {"id": row["slot_id"], "clinic_name": row["clinic_name"],
                     "service": row["service"], "date": row["appointment_date"],
                     "time": row["appointment_time"], "price": row["price"],
                     "doctor_name": row["doctor_name"] if "doctor_name" in row.keys() else "",
                     "doctor_specialty": row["doctor_specialty"] if "doctor_specialty" in row.keys() else ""},
        }

    def get_patient_appointments(self, account_id: int) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT a.id,a.patient_name,a.phone,a.created_at,a.status,
                          EXISTS(SELECT 1 FROM reviews r WHERE r.appointment_id=a.id) AS has_review,
                          s.id AS slot_id,s.clinic_name,
                          s.service,s.appointment_date,s.appointment_time,s.price,
                          s.doctor_name,s.doctor_specialty
                   FROM appointments a JOIN slots s ON s.id=a.slot_id
                   WHERE a.patient_id=? ORDER BY s.appointment_date,s.appointment_time""",
                (account_id,),
            ).fetchall()
        self.send_json(200, [self.appointment_record(row) for row in rows])

    def get_patient_favorites(self, account_id: int) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                "SELECT clinic_name FROM favorites WHERE patient_id=? ORDER BY created_at DESC",
                (account_id,),
            ).fetchall()
        self.send_json(200, [row["clinic_name"] for row in rows])

    def save_patient_favorite(self, account_id: int) -> None:
        try:
            clinic_name = str(self.read_json().get("clinic_name", "")).strip()
        except ValueError as error:
            raise ApiError(400, str(error)) from error
        if not clinic_name or len(clinic_name) > 160:
            raise ApiError(400, "Выберите клинику")
        with connect_db() as connection:
            published = connection.execute(
                """SELECT 1 FROM accounts WHERE role='clinic' AND clinic_status='approved'
                   AND clinic_name=? COLLATE NOCASE
                   UNION SELECT 1 FROM slots s WHERE s.clinic_name=? COLLATE NOCASE
                   AND (s.owner_user_id IS NULL OR EXISTS (
                       SELECT 1 FROM accounts c WHERE c.id=s.owner_user_id
                       AND c.role='clinic' AND c.clinic_status='approved'
                   )) LIMIT 1""",
                (clinic_name, clinic_name),
            ).fetchone()
            if published is None:
                raise ApiError(404, "Клиника больше недоступна")
            connection.execute(
                "INSERT OR IGNORE INTO favorites (patient_id,clinic_name) VALUES (?,?)",
                (account_id, clinic_name),
            )
        self.send_json(200, {"clinic_name": clinic_name, "saved": True})

    def remove_patient_favorite(self, account_id: int, clinic_name: str) -> None:
        with connect_db() as connection:
            connection.execute(
                "DELETE FROM favorites WHERE patient_id=? AND clinic_name=? COLLATE NOCASE",
                (account_id, clinic_name),
            )
        self.send_json(200, {"clinic_name": clinic_name, "saved": False})

    def cancel_patient_appointment(self, appointment_id: int) -> None:
        account = self.require_account("patient")
        with connect_db() as connection:
            row = connection.execute(
                """SELECT a.id,a.status,s.appointment_date,s.appointment_time,s.clinic_name,
                          s.service,s.doctor_name,c.email AS clinic_email,c.clinic_address
                   FROM appointments a JOIN slots s ON s.id=a.slot_id
                   LEFT JOIN accounts c ON c.id=s.owner_user_id AND c.role='clinic'
                   WHERE a.id=? AND a.patient_id=?""",
                (appointment_id, account["id"]),
            ).fetchone()
            if row is None:
                raise ApiError(404, "Запись не найдена")
            appointment_at = datetime.combine(
                date.fromisoformat(row["appointment_date"]),
                datetime.strptime(row["appointment_time"], "%H:%M").time(),
            )
            if row["status"] not in {"pending", "confirmed"}:
                raise ApiError(409, "Эту запись уже нельзя отменить")
            if appointment_at <= datetime.now() + timedelta(hours=2):
                raise ApiError(409, "Отменить запись можно не позднее чем за 2 часа до приёма")
            connection.execute("UPDATE appointments SET status='cancelled' WHERE id=?", (appointment_id,))
        if row["clinic_email"]:
            details = appointment_email_details(
                row["id"], row["clinic_name"], row["service"], row["appointment_date"],
                row["appointment_time"], row["doctor_name"], clinic_address=row["clinic_address"] or "",
            )
            message = (
                "Здравствуйте!\n\nПациент отменил запись. Время снова доступно для записи.\n\n"
                f"{details}\n\nПациент: {account['name']}\nТелефон: {account['phone']}\n"
                f"Почта: {account['email']}\n\nMedQueue — сервис онлайн-записи к стоматологу."
            )
            send_email(row["clinic_email"], "Пациент отменил запись · MedQueue", message)
        self.send_json(200, {"cancelled": True})

    def reschedule_patient_appointment(self, appointment_id: int) -> None:
        account = self.require_account("patient")
        try:
            slot_id = int(self.read_json().get("slot_id", 0))
            if slot_id <= 0:
                raise ValueError
        except (ValueError, TypeError) as error:
            raise ApiError(400, "Выберите новое время") from error
        with connect_db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            appointment = connection.execute(
                """SELECT a.status,s.appointment_date,s.appointment_time,s.clinic_name,s.service,
                          s.doctor_name,s.price,s.owner_user_id,c.email AS clinic_email,c.clinic_address
                   FROM appointments a JOIN slots s ON s.id=a.slot_id
                   LEFT JOIN accounts c ON c.id=s.owner_user_id
                   WHERE a.id=? AND a.patient_id=?""",
                (appointment_id, account["id"]),
            ).fetchone()
            if appointment is None:
                raise ApiError(404, "Запись не найдена")
            old_at = datetime.combine(date.fromisoformat(appointment["appointment_date"]),
                                      datetime.strptime(appointment["appointment_time"], "%H:%M").time())
            if appointment["status"] not in {"pending", "confirmed"} or old_at <= datetime.now() + timedelta(hours=2):
                raise ApiError(409, "Перенести запись можно не позднее чем за 2 часа до приёма")
            slot = connection.execute("SELECT * FROM slots WHERE id=?", (slot_id,)).fetchone()
            if slot is None:
                raise ApiError(404, "Новое время не найдено")
            new_at = datetime.combine(date.fromisoformat(slot["appointment_date"]),
                                      datetime.strptime(slot["appointment_time"], "%H:%M").time())
            if new_at <= datetime.now():
                raise ApiError(409, "Нельзя выбрать прошедшее время")
            try:
                connection.execute("UPDATE appointments SET slot_id=?,status='confirmed' WHERE id=?",
                                   (slot_id, appointment_id))
            except sqlite3.IntegrityError as error:
                raise ApiError(409, "Это время уже занято") from error
            updated = connection.execute("SELECT appointment_date,appointment_time,doctor_name FROM slots WHERE id=?", (slot_id,)).fetchone()
        details = appointment_email_details(appointment_id, appointment["clinic_name"], appointment["service"], updated["appointment_date"], updated["appointment_time"], updated["doctor_name"], appointment["price"], appointment["clinic_address"] or "")
        send_email(account["email"], "Время записи изменено · MedQueue", f"Здравствуйте, {account['name']}!\n\nВы перенесли запись.\n\n{details}")
        if appointment["clinic_email"]:
            send_email(appointment["clinic_email"], "Перенос записи · MedQueue", f"Пациент перенёс запись.\n\n{details}\n\nПациент: {account['name']}\nТелефон: {account['phone']}")
        self.send_json(200, {"rescheduled": True})

    def update_clinic_profile(self) -> None:
        account = self.require_account("clinic")
        try:
            data = self.read_json()
            name = str(data.get("clinic_name", "")).strip()
            address = str(data.get("clinic_address", "")).strip()
            phone = str(data.get("phone", "")).strip()
            email = str(data.get("email", "")).strip().lower()
        except ValueError as error:
            raise ApiError(400, str(error)) from error
        if not 2 <= len(name) <= 160 or len(address) < 3 or len(address) > 240:
            raise ApiError(400, "Проверьте название и адрес клиники")
        if len(re.sub(r"\D", "", phone)) < 7 or len(phone) > 30:
            raise ApiError(400, "Введите корректный телефон")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
            raise ApiError(400, "Введите корректную почту")
        try:
            with connect_db() as connection:
                latitude = data.get("latitude")
                longitude = data.get("longitude")
                try:
                    latitude = float(latitude) if latitude not in (None, "") else None
                    longitude = float(longitude) if longitude not in (None, "") else None
                except (TypeError, ValueError):
                    raise ApiError(400, "Укажите корректные координаты")
                if (latitude is None) != (longitude is None) or (latitude is not None and not (-90 <= latitude <= 90 and -180 <= longitude <= 180)):
                    raise ApiError(400, "Укажите корректные координаты клиники")
                connection.execute("UPDATE accounts SET clinic_name=?,clinic_address=?,phone=?,email=?,latitude=?,longitude=?,email_verified=1 WHERE id=? AND role='clinic'", (name,address,phone,email,latitude,longitude,account["id"]))
                connection.execute("UPDATE slots SET clinic_name=? WHERE owner_user_id=?", (name,account["id"]))
                if name != account["clinic_name"]:
                    connection.execute("UPDATE favorites SET clinic_name=? WHERE clinic_name=? COLLATE NOCASE", (name,account["clinic_name"]))
                fresh = connection.execute("SELECT * FROM accounts WHERE id=?", (account["id"],)).fetchone()
        except sqlite3.IntegrityError as error:
            raise ApiError(409, "Аккаунт с такой почтой уже существует") from error
        self.send_json(200, self.account_record(fresh))

    def upload_clinic_photo(self) -> None:
        account = self.require_account("clinic")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 8 * 1024 * 1024 + 65536:
            raise ApiError(400, "Размер фотографии не должен превышать 8 МБ")
        content_type = self.headers.get("Content-Type", "")
        boundary_match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", content_type)
        if "multipart/form-data" not in content_type or not boundary_match:
            raise ApiError(400, "Выберите файл фотографии")
        boundary = (boundary_match.group(1) or boundary_match.group(2)).encode()
        body = self.rfile.read(length)
        file_data = None
        original_name = "photo"
        for part in body.split(b"--" + boundary):
            headers, separator, data = part.partition(b"\r\n\r\n")
            if not separator or b'name="photos"' not in headers:
                continue
            match = re.search(rb'filename="([^"]*)"', headers)
            if match and match.group(1):
                original_name = Path(match.group(1).decode("utf-8", "ignore")).name
                file_data = data.removesuffix(b"\r\n")
                break
        signatures = {".jpg": lambda b: b.startswith(b"\xff\xd8\xff"), ".jpeg": lambda b: b.startswith(b"\xff\xd8\xff"), ".png": lambda b: b.startswith(b"\x89PNG\r\n\x1a\n"), ".webp": lambda b: len(b) > 12 and b.startswith(b"RIFF") and b[8:12] == b"WEBP"}
        suffix = Path(original_name).suffix.lower()
        if file_data is None or not file_data or len(file_data) > 8 * 1024 * 1024 or suffix not in signatures or not signatures[suffix](file_data):
            raise ApiError(400, "Загрузите изображение JPG, PNG или WebP размером до 8 МБ")
        filename = f"{account['id']}_{secrets.token_hex(16)}{suffix}"
        UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
        (UPLOAD_ROOT / filename).write_bytes(file_data)
        try:
            with connect_db() as connection:
                connection.execute("INSERT INTO clinic_photos (clinic_id,filename) VALUES (?,?)", (account["id"], filename))
                rows = connection.execute("SELECT id,filename FROM clinic_photos WHERE clinic_id=? ORDER BY id DESC", (account["id"],)).fetchall()
                for old in rows[8:]:
                    connection.execute("DELETE FROM clinic_photos WHERE id=?", (old["id"],))
                    (UPLOAD_ROOT / old["filename"]).unlink(missing_ok=True)
        except Exception:
            (UPLOAD_ROOT / filename).unlink(missing_ok=True)
            raise
        self.send_json(201, {"photo": f"/uploads/{filename}"})

    def create_review(self, appointment_id: int) -> None:
        account = self.require_account("patient")
        try:
            data = self.read_json()
            rating = int(data.get("rating", 0))
            comment = str(data.get("comment", "")).strip()
            if rating not in range(1, 6) or len(comment) > 1000:
                raise ValueError
        except (ValueError, TypeError) as error:
            raise ApiError(400, "Выберите оценку от 1 до 5; комментарий — до 1000 символов") from error
        with connect_db() as connection:
            appointment = connection.execute(
                """SELECT a.id,a.status,s.clinic_name,s.appointment_date,s.appointment_time FROM appointments a
                   JOIN slots s ON s.id=a.slot_id WHERE a.id=? AND a.patient_id=?""",
                (appointment_id, account["id"]),
            ).fetchone()
            if appointment is None:
                raise ApiError(404, "Запись не найдена")
            if appointment["status"] == "cancelled":
                raise ApiError(409, "Для отменённой записи нельзя оставить отзыв")
            appointment_at = datetime.combine(date.fromisoformat(appointment["appointment_date"]),
                                              datetime.strptime(appointment["appointment_time"], "%H:%M").time())
            if appointment_at > datetime.now():
                raise ApiError(409, "Оставить отзыв можно после приёма")
            try:
                connection.execute("""INSERT INTO reviews
                    (appointment_id,patient_id,clinic_name,rating,comment) VALUES (?,?,?,?,?)""",
                    (appointment_id, account["id"], appointment["clinic_name"], rating, comment))
            except sqlite3.IntegrityError as error:
                raise ApiError(409, "Вы уже оставили отзыв об этой записи") from error
        self.send_json(201, {"saved": True})

    def get_clinic_reviews(self, clinic_name: str) -> None:
        with connect_db() as connection:
            rows = connection.execute("""SELECT r.rating,r.comment,r.created_at
                FROM reviews r WHERE r.clinic_name=? COLLATE NOCASE ORDER BY r.created_at DESC""", (clinic_name,)).fetchall()
        self.send_json(200, [dict(row) for row in rows])

    def cancel_clinic_appointment(self, appointment_id: int) -> None:
        account = self.require_account("clinic", approved_clinic=True)
        with connect_db() as connection:
            row = connection.execute(
                """SELECT a.id,a.status,a.patient_name,p.email AS patient_email,
                          s.appointment_date,s.appointment_time,s.clinic_name,s.service,s.doctor_name
                   FROM appointments a JOIN slots s ON s.id=a.slot_id
                   LEFT JOIN accounts p ON p.id=a.patient_id
                   WHERE a.id=? AND s.owner_user_id=?""",
                (appointment_id, account["id"]),
            ).fetchone()
            if row is None:
                raise ApiError(404, "Запись не найдена в расписании вашей клиники")
            appointment_at = datetime.combine(
                date.fromisoformat(row["appointment_date"]),
                datetime.strptime(row["appointment_time"], "%H:%M").time(),
            )
            if row["status"] not in {"pending", "confirmed"} or appointment_at <= datetime.now():
                raise ApiError(409, "Эту запись уже нельзя отменить")
            connection.execute("UPDATE appointments SET status='cancelled' WHERE id=?", (appointment_id,))
        if row["patient_email"]:
            details = appointment_email_details(
                row["id"], row["clinic_name"], row["service"], row["appointment_date"],
                row["appointment_time"], row["doctor_name"], clinic_address=account["clinic_address"] or "",
            )
            message = (
                f"Здравствуйте, {row['patient_name']}!\n\nКлиника сообщила, что не сможет принять вас "
                "в это время. Пожалуйста, свяжитесь с клиникой, чтобы выбрать другое время.\n\n"
                f"{details}\nТелефон клиники: {account['phone']}\n\n"
                "Извините за неудобство.\nMedQueue — сервис онлайн-записи к стоматологу."
            )
            send_email(row["patient_email"], "Клиника отменила запись · MedQueue", message)
        self.send_json(200, {"cancelled": True})

    def get_clinic_slots(self, account_id: int) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT s.*,EXISTS(SELECT 1 FROM appointments a WHERE a.slot_id=s.id
                   AND a.status IN ('pending','confirmed')) AS booked
                   FROM slots s WHERE s.owner_user_id=? ORDER BY s.appointment_date,s.appointment_time""",
                (account_id,),
            ).fetchall()
        self.send_json(200, [slot_record(row, bool(row["booked"])) for row in rows])

    def get_clinic_appointments(self, account_id: int) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT a.id,a.patient_name,a.phone,a.created_at,a.status,s.id AS slot_id,s.clinic_name,
                   s.service,s.appointment_date,s.appointment_time,s.price,s.doctor_name,s.doctor_specialty
                   FROM appointments a JOIN slots s ON s.id=a.slot_id
                   WHERE s.owner_user_id=? AND a.status IN ('pending','confirmed')
                   ORDER BY s.appointment_date,s.appointment_time""",
                (account_id,),
            ).fetchall()
        self.send_json(200, [self.appointment_record(row) for row in rows])

    def get_admin_overview(self) -> None:
        with connect_db() as connection:
            stats = {
                "patients": connection.execute("SELECT COUNT(*) FROM accounts WHERE role='patient'").fetchone()[0],
                "clinics": connection.execute("SELECT COUNT(*) FROM accounts WHERE role='clinic'").fetchone()[0],
                "clinics_pending": connection.execute("SELECT COUNT(*) FROM accounts WHERE role='clinic' AND clinic_status='pending'").fetchone()[0],
                "clinics_approved": connection.execute("SELECT COUNT(*) FROM accounts WHERE role='clinic' AND clinic_status='approved'").fetchone()[0],
                "appointments": connection.execute("SELECT COUNT(*) FROM appointments").fetchone()[0],
                "slots_available": connection.execute("SELECT COUNT(*) FROM slots s WHERE NOT EXISTS(SELECT 1 FROM appointments a WHERE a.slot_id=s.id AND a.status IN ('pending','confirmed'))").fetchone()[0],
                "slots_booked": connection.execute("SELECT COUNT(*) FROM appointments WHERE status IN ('pending','confirmed')").fetchone()[0],
            }
        self.send_json(200, stats)

    def get_admin_users(self) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                "SELECT id,name,email,phone,role,clinic_name,clinic_status,created_at FROM accounts ORDER BY created_at DESC"
            ).fetchall()
        self.send_json(200, [dict(row) for row in rows])

    def get_admin_clinics(self) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                "SELECT id,name,email,phone,clinic_name,clinic_address,clinic_status,created_at FROM accounts WHERE role='clinic' ORDER BY created_at DESC"
            ).fetchall()
        self.send_json(200, [dict(row) for row in rows])

    def delete_admin_clinic(self, clinic_id: int) -> None:
        self.require_account("admin")
        with connect_db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            clinic = connection.execute(
                "SELECT clinic_name FROM accounts WHERE id=? AND role='clinic'", (clinic_id,)
            ).fetchone()
            if clinic is None:
                raise ApiError(404, "Клиника не найдена")
            connection.execute(
                "DELETE FROM appointments WHERE slot_id IN (SELECT id FROM slots WHERE owner_user_id=?)",
                (clinic_id,),
            )
            connection.execute("DELETE FROM slots WHERE owner_user_id=?", (clinic_id,))
            connection.execute(
                "DELETE FROM favorites WHERE clinic_name=? COLLATE NOCASE", (clinic["clinic_name"],)
            )
            connection.execute("DELETE FROM accounts WHERE id=?", (clinic_id,))
        self.send_json(200, {"deleted": True, "clinic_id": clinic_id})

    def get_clinic_doctors(self, clinic_id: int) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                "SELECT id,name,specialty,experience FROM doctors WHERE clinic_id=? ORDER BY name COLLATE NOCASE",
                (clinic_id,),
            ).fetchall()
        self.send_json(200, [dict(row) for row in rows])

    def save_clinic_doctor(self) -> None:
        account = self.require_account("clinic", approved_clinic=True)
        try:
            data = self.read_json()
            doctor_id = int(data.get("doctor_id") or 0)
            name = str(data.get("name", "")).strip()
            specialty = str(data.get("specialty", "")).strip()
            experience = int(data.get("experience", 0))
            if not 2 <= len(name) <= 100 or not 2 <= len(specialty) <= 120 or not 0 <= experience <= 60:
                raise ValueError
        except (ValueError, TypeError):
            raise ApiError(400, "Заполните имя врача, специальность и корректный стаж")

        try:
            with connect_db() as connection:
                if doctor_id:
                    cursor = connection.execute(
                        "UPDATE doctors SET name=?,specialty=?,experience=? WHERE id=? AND clinic_id=?",
                        (name, specialty, experience, doctor_id, account["id"]),
                    )
                    if cursor.rowcount == 0:
                        raise ApiError(404, "Врач не найден в вашей клинике")
                    connection.execute(
                        """UPDATE slots SET doctor_name=?,doctor_specialty=? WHERE doctor_id=?
                           AND NOT EXISTS (SELECT 1 FROM appointments a WHERE a.slot_id=slots.id)""",
                        (name, specialty, doctor_id),
                    )
                else:
                    cursor = connection.execute(
                        "INSERT INTO doctors (clinic_id,name,specialty,experience) VALUES (?,?,?,?)",
                        (account["id"], name, specialty, experience),
                    )
                    doctor_id = cursor.lastrowid
                doctor = connection.execute(
                    "SELECT id,name,specialty,experience FROM doctors WHERE id=? AND clinic_id=?",
                    (doctor_id, account["id"]),
                ).fetchone()
        except sqlite3.IntegrityError as error:
            raise ApiError(409, "Врач с таким именем уже добавлен") from error
        self.send_json(200, dict(doctor))

    def delete_clinic_doctor(self, doctor_id: int) -> None:
        account = self.require_account("clinic", approved_clinic=True)
        with connect_db() as connection:
            doctor = connection.execute(
                "SELECT name FROM doctors WHERE id=? AND clinic_id=?", (doctor_id, account["id"])
            ).fetchone()
            if doctor is None:
                raise ApiError(404, "Врач не найден в вашей клинике")
            assigned = connection.execute(
                """SELECT 1 FROM slots s WHERE s.doctor_id=? AND
                   (s.appointment_date > date('now') OR
                    (s.appointment_date=date('now') AND s.appointment_time >= time('now')) OR
                    EXISTS (SELECT 1 FROM appointments a WHERE a.slot_id=s.id
                            AND a.status IN ('pending','confirmed'))) LIMIT 1""",
                (doctor_id,),
            ).fetchone()
            if assigned:
                raise ApiError(409, "Нельзя удалить врача, пока к нему привязаны слоты расписания")
            connection.execute("DELETE FROM doctors WHERE id=? AND clinic_id=?", (doctor_id, account["id"]))
        self.send_json(200, {"deleted": True, "doctor_id": doctor_id})

    def decide_clinic(self) -> None:
        self.require_account("admin")
        try:
            data = self.read_json()
            account_id = int(data.get("clinic_id", 0))
            status = str(data.get("status", ""))
        except (ValueError, TypeError) as error:
            raise ApiError(400, "Некорректная заявка") from error
        if account_id < 1 or status not in {"approved", "rejected", "pending"}:
            raise ApiError(400, "Некорректное решение")
        with connect_db() as connection:
            cursor = connection.execute(
                "UPDATE accounts SET clinic_status=? WHERE id=? AND role='clinic'",
                (status, account_id),
            )
        if cursor.rowcount == 0:
            raise ApiError(404, "Клиника не найдена")
        self.send_json(200, {"id": account_id, "status": status})

    # Направляем GET-запросы к API или отдаём HTML-файлы сайта.
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            if path == "/api/auth/verify-email":
                self.verify_email(parse_qs(parsed.query).get("token", [""])[0])
            elif path == "/api/slots":
                self.get_slots(parse_qs(parsed.query))
            elif path == "/api/clinics":
                self.get_clinics()
            elif path == "/api/reviews":
                clinic_name = parse_qs(parsed.query).get("clinic_name", [""])[0].strip()
                if not clinic_name:
                    raise ApiError(400, "Укажите клинику")
                self.get_clinic_reviews(clinic_name)
            elif re.fullmatch(r"/api/slots/\d+", path):
                self.get_slot(int(path.rsplit("/", 1)[1]))
            elif path == "/api/appointments":
                self.get_appointments()
            elif path == "/api/me":
                account = self.current_account()
                if account is None:
                    raise ApiError(401, "Войдите в аккаунт")
                self.send_json(200, self.account_record(account))
            elif path == "/api/patient/appointments":
                account = self.require_account("patient")
                self.get_patient_appointments(account["id"])
            elif path == "/api/patient/favorites":
                account = self.require_account("patient")
                self.get_patient_favorites(account["id"])
            elif path == "/api/clinic/profile":
                account = self.require_account("clinic")
                self.send_json(200, self.account_record(account))
            elif path == "/api/clinic/photos":
                account = self.require_account("clinic")
                with connect_db() as connection:
                    photos = connection.execute("SELECT id, '/uploads/' || filename AS url FROM clinic_photos WHERE clinic_id=? ORDER BY id DESC", (account["id"],)).fetchall()
                self.send_json(200, [dict(photo) for photo in photos])
            elif path == "/api/clinic/doctors":
                account = self.require_account("clinic", approved_clinic=True)
                self.get_clinic_doctors(account["id"])
            elif path == "/api/clinic/slots":
                account = self.require_account("clinic", approved_clinic=True)
                self.get_clinic_slots(account["id"])
            elif path == "/api/clinic/appointments":
                account = self.require_account("clinic", approved_clinic=True)
                self.get_clinic_appointments(account["id"])
            elif path == "/api/admin/overview":
                self.require_account("admin")
                self.get_admin_overview()
            elif path == "/api/admin/users":
                self.require_account("admin")
                self.get_admin_users()
            elif path == "/api/admin/clinics":
                self.require_account("admin")
                self.get_admin_clinics()
            else:
                self.serve_static(path)
        except ApiError as error:
            self.send_error_json(error)

    # POST используется для добавления слотов и создания записи пациента.
    def do_POST(self) -> None:
        path = urlsplit(self.path).path.rstrip("/")
        try:
            if path == "/api/register":
                self.register_account()
            elif path == "/api/login":
                self.login()
            elif path == "/api/auth/verify-email":
                self.request_verification()
            elif path == "/api/auth/password-reset":
                self.request_password_reset()
            elif path == "/api/auth/password-reset/confirm":
                self.reset_password()
            elif path == "/api/logout":
                self.logout()
            elif path == "/api/slots":
                self.create_slot()
            elif path == "/api/appointments":
                self.create_appointment()
            elif re.fullmatch(r"/api/patient/appointments/\d+/reschedule", path):
                self.reschedule_patient_appointment(int(path.split("/")[4]))
            elif re.fullmatch(r"/api/patient/appointments/\d+/reviews", path):
                self.create_review(int(path.split("/")[4]))
            elif path == "/api/patient/favorites":
                account = self.require_account("patient")
                self.save_patient_favorite(account["id"])
            elif path == "/api/admin/clinic-decision":
                self.decide_clinic()
            elif path == "/api/clinic/doctors":
                self.save_clinic_doctor()
            elif path == "/api/clinic/photos":
                self.upload_clinic_photo()
            else:
                self.send_json(404, {"error": "Маршрут не найден"})
        except ApiError as error:
            self.send_error_json(error)

    def do_PUT(self) -> None:
        path = urlsplit(self.path).path.rstrip("/")
        try:
            if path == "/api/clinic/profile":
                self.update_clinic_profile()
            else:
                self.send_json(404, {"error": "Маршрут не найден"})
        except ApiError as error:
            self.send_error_json(error)

    # DELETE разрешён только для свободных временных слотов.
    def do_DELETE(self) -> None:
        path = urlsplit(self.path).path.rstrip("/")
        match = re.fullmatch(r"/api/slots/(\d+)", path)
        patient_appointment = re.fullmatch(r"/api/patient/appointments/(\d+)", path)
        clinic_appointment = re.fullmatch(r"/api/clinic/appointments/(\d+)", path)
        favorite = re.fullmatch(r"/api/patient/favorites/(.+)", path)
        admin_clinic = re.fullmatch(r"/api/admin/clinics/(\d+)", path)
        clinic_doctor = re.fullmatch(r"/api/clinic/doctors/(\d+)", path)
        try:
            if admin_clinic:
                self.delete_admin_clinic(int(admin_clinic.group(1)))
            elif clinic_doctor:
                self.delete_clinic_doctor(int(clinic_doctor.group(1)))
            elif match:
                self.delete_slot(int(match.group(1)))
            elif patient_appointment:
                self.cancel_patient_appointment(int(patient_appointment.group(1)))
            elif clinic_appointment:
                self.cancel_clinic_appointment(int(clinic_appointment.group(1)))
            elif favorite:
                account = self.require_account("patient")
                self.remove_patient_favorite(account["id"], unquote(favorite.group(1)))
            else:
                self.send_json(404, {"error": "Маршрут не найден"})
        except ApiError as error:
            self.send_error_json(error)

    # Отдаём расписание; параметр all=1 нужен админке, чтобы видеть занятые слоты.
    def get_slots(self, query: dict[str, list[str]]) -> None:
        include_booked = query.get("all", ["0"])[0] == "1"
        clinic_name = query.get("clinic_name", [""])[0].strip()
        account = None
        if include_booked:
            account = self.current_account()
            if account is None or account["role"] not in {"admin", "clinic"}:
                raise ApiError(403, "Войдите в аккаунт клиники")
            if account["role"] == "clinic" and account["clinic_status"] != "approved":
                raise ApiError(403, "Заявка клиники ещё не одобрена")
        # По умолчанию скрываем занятые слоты; админка передаёт all=1.
        sql = """
            SELECT s.*, EXISTS(
                SELECT 1 FROM appointments a WHERE a.slot_id = s.id AND a.status IN ('pending','confirmed')
            ) AS booked
            FROM slots s
        """
        params: list = []
        if not include_booked:
            sql += """ WHERE NOT EXISTS (SELECT 1 FROM appointments a WHERE a.slot_id = s.id AND a.status IN ('pending','confirmed'))
                       AND s.owner_user_id IS NOT NULL
                       AND EXISTS (
                           SELECT 1 FROM accounts c WHERE c.id=s.owner_user_id
                           AND c.role='clinic' AND c.clinic_status='approved'
                       )"""
            if clinic_name:
                sql += " AND s.clinic_name=? COLLATE NOCASE"
                params.append(clinic_name)
        elif account and account["role"] == "clinic":
            sql += " WHERE s.owner_user_id = ?"
            params.append(account["id"])
        sql += " ORDER BY s.appointment_date, s.appointment_time"
        with connect_db() as connection:
            rows = connection.execute(sql, params).fetchall()
        self.send_json(200, [slot_record(row, bool(row["booked"])) for row in rows])

    def get_clinics(self) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT a.id,a.clinic_name AS name,a.clinic_address AS address,a.phone,a.latitude,a.longitude,
                          (SELECT '/uploads/' || p.filename FROM clinic_photos p WHERE p.clinic_id=a.id ORDER BY p.id DESC LIMIT 1) AS photo
                   FROM accounts a WHERE a.role='clinic' AND a.clinic_status='approved'
                   ORDER BY a.clinic_name COLLATE NOCASE"""
            ).fetchall()
            clinics = []
            for row in rows:
                clinic = dict(row)
                clinic["photos"] = [photo["url"] for photo in connection.execute(
                    "SELECT '/uploads/' || filename AS url FROM clinic_photos WHERE clinic_id=? ORDER BY id DESC", (row["id"],)
                ).fetchall()]
                clinics.append(clinic)
        self.send_json(200, clinics)

    # По ID загружаем детали слота перед показом формы подтверждения.
    def get_slot(self, slot_id: int) -> None:
        with connect_db() as connection:
            row = connection.execute(
                """SELECT s.*, EXISTS(
                       SELECT 1 FROM appointments a WHERE a.slot_id = s.id AND a.status IN ('pending','confirmed')
                   ) AS booked
                   FROM slots s WHERE s.id = ?""",
                (slot_id,),
            ).fetchone()
        if row is None:
            self.send_json(404, {"error": "Время приёма не найдено"})
            return
        if row["owner_user_id"] is None:
            self.send_json(404, {"error": "Клиника не принимает запись"})
            return
        with connect_db() as connection:
            clinic = connection.execute(
                "SELECT clinic_status FROM accounts WHERE id=? AND role='clinic'",
                (row["owner_user_id"],),
            ).fetchone()
        if clinic is None or clinic["clinic_status"] != "approved":
            self.send_json(404, {"error": "Клиника не принимает запись"})
            return
        self.send_json(200, slot_record(row, bool(row["booked"])))

    # Админка получает список пациентов вместе с выбранной услугой и временем.
    def get_appointments(self) -> None:
        account = self.current_account()
        if account is None or account["role"] not in {"admin", "clinic"}:
            raise ApiError(403, "Войдите в аккаунт клиники")
        if account["role"] == "clinic" and account["clinic_status"] != "approved":
            raise ApiError(403, "Заявка клиники ещё не одобрена")
        scope = "WHERE a.status IN ('pending','confirmed') AND s.owner_user_id=?" if account["role"] == "clinic" else "WHERE a.status IN ('pending','confirmed')"
        with connect_db() as connection:
            rows = connection.execute(
                f"""SELECT a.id, a.patient_name, a.phone, a.created_at,a.status,
                          s.id AS slot_id, s.clinic_name, s.service,
                          s.appointment_date, s.appointment_time, s.price,
                          s.doctor_name,s.doctor_specialty
                   FROM appointments a JOIN slots s ON s.id = a.slot_id {scope}
                   ORDER BY s.appointment_date, s.appointment_time"""
                , (account["id"],) if account["role"] == "clinic" else ()
            ).fetchall()
        self.send_json(200, [self.appointment_record(row) for row in rows])

    # Проверяем дату, время и цену, затем добавляем новый слот в SQLite.
    def create_slot(self) -> None:
        account = self.require_account("clinic", approved_clinic=True)
        try:
            data = self.read_json()
            # Сначала проверяем обязательные поля и не принимаем время в прошлом.
            clinic_name = account["clinic_name"]
            doctor_id = int(data.get("doctor_id", 0))
            service = str(data.get("service", "")).strip()
            appointment_date = str(data.get("date", "")).strip()
            appointment_time = str(data.get("time", "")).strip()
            price = int(data.get("price", 0))
            parsed_date = date.fromisoformat(appointment_date)
            parsed_time = datetime.strptime(appointment_time, "%H:%M").time()
            if not clinic_name or doctor_id <= 0 or not service or datetime.combine(parsed_date, parsed_time) <= datetime.now() or price <= 0:
                raise ValueError
        except (ValueError, TypeError):
            self.send_json(400, {"error": "Выберите врача, услугу, дату, время и укажите корректную цену"})
            return

        try:
            with connect_db() as connection:
                doctor = connection.execute(
                    "SELECT name,specialty FROM doctors WHERE id=? AND clinic_id=?",
                    (doctor_id, account["id"]),
                ).fetchone()
                if doctor is None:
                    raise ApiError(400, "Выберите врача из списка вашей клиники")
                cursor = connection.execute(
                    """INSERT INTO slots
                       (clinic_name, service, appointment_date, appointment_time, price, owner_user_id, doctor_id,
                        doctor_name, doctor_specialty)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (clinic_name, service, appointment_date, appointment_time, price, account["id"], doctor_id,
                     doctor["name"], doctor["specialty"]),
                )
                slot_id = cursor.lastrowid
                row = connection.execute("SELECT * FROM slots WHERE id = ?", (slot_id,)).fetchone()
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "На это время уже создан слот"})
            return
        self.send_json(201, slot_record(row))

    # Нельзя удалить слот, на который уже записан пациент.
    def delete_slot(self, slot_id: int) -> None:
        account = self.current_account()
        if account is None or account["role"] not in {"admin", "clinic"}:
            raise ApiError(403, "Войдите в аккаунт клиники")
        with connect_db() as connection:
            row = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM appointments WHERE slot_id = ? AND status IN ('pending','confirmed'))", (slot_id,)
            ).fetchone()
            exists = connection.execute("SELECT owner_user_id FROM slots WHERE id = ?", (slot_id,)).fetchone()
            if exists is None:
                self.send_json(404, {"error": "Слот не найден"})
                return
            if account["role"] == "clinic" and (
                account["clinic_status"] != "approved" or exists["owner_user_id"] != account["id"]
            ):
                raise ApiError(403, "Можно менять только расписание своей одобренной клиники")
            if row[0]:
                self.send_json(409, {"error": "Нельзя удалить слот с записью пациента"})
                return
            connection.execute("DELETE FROM slots WHERE id = ?", (slot_id,))
        self.send_json(200, {"deleted": True})

    # BEGIN IMMEDIATE и UNIQUE slot_id не дают двум запросам занять один слот.
    def create_appointment(self) -> None:
        account = self.require_account("patient")
        try:
            data = self.read_json()
            slot_id = int(data.get("slot_id", 0))
            if slot_id <= 0:
                raise ValueError
        except (ValueError, TypeError):
            self.send_json(400, {"error": "Введите имя, корректный телефон и выберите время"})
            return

        try:
            with connect_db() as connection:
                # Блокируем запись на время транзакции, пока проверяем доступность слота.
                connection.execute("BEGIN IMMEDIATE")
                slot = connection.execute(
                    "SELECT * FROM slots WHERE id = ?",
                    (slot_id,),
                ).fetchone()
                if slot is None or datetime.combine(
                    date.fromisoformat(slot["appointment_date"]),
                    datetime.strptime(slot["appointment_time"], "%H:%M").time(),
                ) <= datetime.now():
                    connection.rollback()
                    self.send_json(404, {"error": "Это время уже недоступно. Обновите список слотов."})
                    return
                if slot["owner_user_id"] is not None:
                    clinic = connection.execute(
                        "SELECT clinic_status FROM accounts WHERE id=? AND role='clinic'",
                        (slot["owner_user_id"],),
                    ).fetchone()
                    if clinic is None or clinic["clinic_status"] != "approved":
                        connection.rollback()
                        self.send_json(404, {"error": "Клиника не принимает запись"})
                        return
                cursor = connection.execute(
                    "INSERT INTO appointments (slot_id, patient_name, phone, patient_id) VALUES (?, ?, ?, ?)",
                    (slot_id, account["name"], account["phone"], account["id"]),
                )
                appointment_id = cursor.lastrowid
                clinic_email = None
                clinic_address = ""
                if slot["owner_user_id"] is not None:
                    clinic_account = connection.execute(
                        "SELECT email,clinic_address FROM accounts WHERE id=? AND role='clinic' AND clinic_status='approved'",
                        (slot["owner_user_id"],),
                    ).fetchone()
                    clinic_email = clinic_account["email"] if clinic_account else None
                    clinic_address = clinic_account["clinic_address"] if clinic_account else ""
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "Это время уже заняли. Выберите другое."})
            return

        details = appointment_email_details(
            appointment_id,
            slot["clinic_name"],
            slot["service"],
            slot["appointment_date"],
            slot["appointment_time"],
            slot["doctor_name"],
            slot["price"],
            clinic_address,
        )
        patient_message = (
            f"Здравствуйте, {account['name']}!\n\nВы записаны на приём. Будем ждать вас в клинике.\n\n"
            f"{details}\n\nЕсли планы изменятся, запись можно отменить в личном кабинете "
            "не позднее чем за 2 часа до приёма.\n\nMedQueue — сервис онлайн-записи к стоматологу."
        )
        send_email(account["email"], "Ваша запись подтверждена · MedQueue", patient_message)
        if clinic_email:
            clinic_message = (
                "Здравствуйте!\n\nВ вашей клинике появилась новая запись.\n\n"
                f"{details}\n\nПациент: {account['name']}\nТелефон: {account['phone']}\n"
                f"Почта: {account['email']}\n\nMedQueue — сервис онлайн-записи к стоматологу."
            )
            send_email(
                clinic_email,
                "Новая запись в вашей клинике · MedQueue",
                clinic_message,
            )

        self.send_json(
            201,
            {
                "id": appointment_id,
                "patient_name": account["name"],
                "phone": account["phone"],
                "slot": slot_record(slot),
            },
        )

    # Отдаём только файлы внутри папки MedQueue, не открывая доступ к остальному проекту.
    def serve_static(self, request_path: str) -> None:
        relative_path = "index.html" if request_path == "/" else unquote(request_path).lstrip("/")
        if relative_path.startswith("uploads/"):
            upload_name = Path(relative_path.removeprefix("uploads/")).name
            file_path = (UPLOAD_ROOT / upload_name).resolve()
            allowed_root = UPLOAD_ROOT.resolve()
        else:
            file_path = (WEB_ROOT / relative_path).resolve()
            allowed_root = WEB_ROOT.resolve()
        if allowed_root not in file_path.parents or not file_path.is_file():
            self.send_error(404, "File not found")
            return
        content = file_path.read_bytes()
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript",):
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)


if __name__ == "__main__":
    # При запуске создаём базу и поднимаем локальный HTTP-сервер.
    initialize_database()
    httpd = ThreadingHTTPServer((HOST, PORT), MedQueueHandler)
    print(f"MedQueue запущен на порту {PORT}")
    print(f"SQLite база: {DATABASE}")
    hosted = any(os.environ.get(key) for key in ("RENDER", "RENDER_EXTERNAL_URL", "RENDER_SERVICE_ID"))
    if not hosted and not os.environ.get("SITE_ADMIN_PASSWORD"):
        print("Локальный вход владельца: admin@medqueue.local / MedQueue123!")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
    finally:
        httpd.server_close()
