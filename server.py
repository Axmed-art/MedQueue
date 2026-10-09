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
from urllib.parse import parse_qs, unquote, urlsplit


# Пути заданы относительно этого файла, поэтому сервер можно запускать из любой папки.
ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "MedQueue"
DATABASE = ROOT / "medqueue.db"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
SESSION_COOKIE = "medqueue_session"
SESSION_DAYS = 14


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


# Создаём таблицы при запуске; демо-слоты добавляются только в новую базу.
def initialize_database() -> None:
    is_new_database = not DATABASE.exists()
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

            -- Одна запись занимает один слот; UNIQUE не допускает повторное бронирование.
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slot_id INTEGER NOT NULL UNIQUE REFERENCES slots(id) ON DELETE RESTRICT,
                patient_name TEXT NOT NULL,
                phone TEXT NOT NULL,
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
                clinic_status TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            """
        )

        slot_columns = {row["name"] for row in connection.execute("PRAGMA table_info(slots)")}
        if "owner_user_id" not in slot_columns:
            connection.execute("ALTER TABLE slots ADD COLUMN owner_user_id INTEGER REFERENCES accounts(id)")
        appointment_columns = {row["name"] for row in connection.execute("PRAGMA table_info(appointments)")}
        if "patient_id" not in appointment_columns:
            connection.execute("ALTER TABLE appointments ADD COLUMN patient_id INTEGER REFERENCES accounts(id)")

        admin_email = os.environ.get("SITE_ADMIN_EMAIL", "").strip().lower()
        admin_password = os.environ.get("SITE_ADMIN_PASSWORD", "")
        hosted = any(os.environ.get(key) for key in ("RENDER", "RENDER_EXTERNAL_URL", "RENDER_SERVICE_ID"))
        local_demo_admin = not hosted
        if local_demo_admin:
            admin_email = admin_email or "admin@medqueue.local"
            admin_password = admin_password or "MedQueue123!"
        if admin_email and admin_password:
            exists = connection.execute("SELECT 1 FROM accounts WHERE email=? COLLATE NOCASE", (admin_email,)).fetchone()
            if not exists:
                salt, digest = password_digest(admin_password)
                connection.execute(
                    "INSERT INTO accounts (name,email,phone,password_salt,password_hash,role) VALUES (?,?, '', ?, ?, 'admin')",
                    ("Администратор MedQueue", admin_email, salt, digest),
                )

        # Тестовое расписание нужно для первого показа; существующую базу не перезаписываем.
        if is_new_database:
            tomorrow = date.today() + timedelta(days=1)
            day_after = date.today() + timedelta(days=2)
            demo_slots = [
                ("Smile Clinic", "Лечение кариеса", tomorrow.isoformat(), "10:00", 15000),
                ("Smile Clinic", "Профессиональная чистка", tomorrow.isoformat(), "12:30", 12000),
                ("Smile Clinic", "Острая боль", tomorrow.isoformat(), "15:00", 8000),
                ("Smile Clinic", "Лечение кариеса", day_after.isoformat(), "11:00", 15000),
                ("Smile Clinic", "Профессиональная чистка", day_after.isoformat(), "14:00", 12000),
                ("Smile Clinic", "Острая боль", day_after.isoformat(), "17:00", 8000),
            ]
            connection.executemany(
                """INSERT INTO slots
                   (clinic_name, service, appointment_date, appointment_time, price)
                   VALUES (?, ?, ?, ?, ?)""",
                demo_slots,
            )


# Преобразуем строку SQLite в JSON-объект для страниц сайта.
def slot_record(row: sqlite3.Row, booked: bool = False) -> dict:
    return {
        "id": row["id"],
        "clinic_name": row["clinic_name"],
        "service": row["service"],
        "date": row["appointment_date"],
        "time": row["appointment_time"],
        "price": row["price"],
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
            "clinic_status": account["clinic_status"],
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
                       (name,email,phone,password_salt,password_hash,role,clinic_name,clinic_address,clinic_status)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (name, email, phone, salt, digest, role, clinic_name or None,
                     clinic_address or None, "pending" if role == "clinic" else None),
                )
                account_id = cursor.lastrowid
                if role == "clinic" and clinic_name.casefold() == "smile clinic":
                    connection.execute(
                        "UPDATE slots SET owner_user_id=? WHERE owner_user_id IS NULL AND clinic_name=? COLLATE NOCASE",
                        (account_id, clinic_name),
                    )
                account = connection.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        except sqlite3.IntegrityError as error:
            raise ApiError(409, "Аккаунт с такой почтой уже существует") from error
        session = self.make_session(account_id)
        self.send_json(201, self.account_record(account), session)

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

    def logout(self) -> None:
        account = self.current_account()
        if account:
            with connect_db() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (account["token_hash"],))
        self.send_json(200, {"logged_out": True}, ("", 0))

    @staticmethod
    def appointment_record(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "patient_name": row["patient_name"], "phone": row["phone"],
            "created_at": row["created_at"],
            "slot": {"id": row["slot_id"], "clinic_name": row["clinic_name"],
                     "service": row["service"], "date": row["appointment_date"],
                     "time": row["appointment_time"], "price": row["price"]},
        }

    def get_patient_appointments(self, account_id: int) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT a.id,a.patient_name,a.phone,a.created_at,s.id AS slot_id,s.clinic_name,
                          s.service,s.appointment_date,s.appointment_time,s.price
                   FROM appointments a JOIN slots s ON s.id=a.slot_id
                   WHERE a.patient_id=? ORDER BY s.appointment_date,s.appointment_time""",
                (account_id,),
            ).fetchall()
        self.send_json(200, [self.appointment_record(row) for row in rows])

    def get_clinic_slots(self, account_id: int) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT s.*,EXISTS(SELECT 1 FROM appointments a WHERE a.slot_id=s.id) AS booked
                   FROM slots s WHERE s.owner_user_id=? ORDER BY s.appointment_date,s.appointment_time""",
                (account_id,),
            ).fetchall()
        self.send_json(200, [slot_record(row, bool(row["booked"])) for row in rows])

    def get_clinic_appointments(self, account_id: int) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT a.id,a.patient_name,a.phone,a.created_at,s.id AS slot_id,s.clinic_name,
                          s.service,s.appointment_date,s.appointment_time,s.price
                   FROM appointments a JOIN slots s ON s.id=a.slot_id
                   WHERE s.owner_user_id=? ORDER BY s.appointment_date,s.appointment_time""",
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
                "slots_available": connection.execute("SELECT COUNT(*) FROM slots s WHERE NOT EXISTS(SELECT 1 FROM appointments a WHERE a.slot_id=s.id)").fetchone()[0],
                "slots_booked": connection.execute("SELECT COUNT(*) FROM appointments").fetchone()[0],
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

    def decide_clinic(self) -> None:
        self.require_account("admin")
        try:
            data = self.read_json()
            account_id = int(data.get("clinic_id", 0))
            status = str(data.get("status", ""))
        except (ValueError, TypeError) as error:
            raise ApiError(400, "Некорректная заявка") from error
        if account_id < 1 or status not in {"approved", "rejected"}:
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
            if path == "/api/slots":
                self.get_slots(parse_qs(parsed.query))
            elif path == "/api/clinics":
                self.get_clinics()
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
            elif path == "/api/clinic/profile":
                account = self.require_account("clinic")
                self.send_json(200, self.account_record(account))
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
            elif path == "/api/logout":
                self.logout()
            elif path == "/api/slots":
                self.create_slot()
            elif path == "/api/appointments":
                self.create_appointment()
            elif path == "/api/admin/clinic-decision":
                self.decide_clinic()
            else:
                self.send_json(404, {"error": "Маршрут не найден"})
        except ApiError as error:
            self.send_error_json(error)

    # DELETE разрешён только для свободных временных слотов.
    def do_DELETE(self) -> None:
        path = urlsplit(self.path).path.rstrip("/")
        match = re.fullmatch(r"/api/slots/(\d+)", path)
        try:
            if match:
                self.delete_slot(int(match.group(1)))
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
                SELECT 1 FROM appointments a WHERE a.slot_id = s.id
            ) AS booked
            FROM slots s
        """
        params: list = []
        if not include_booked:
            sql += """ WHERE NOT EXISTS (SELECT 1 FROM appointments a WHERE a.slot_id = s.id)
                       AND (s.owner_user_id IS NULL OR EXISTS (
                           SELECT 1 FROM accounts c WHERE c.id=s.owner_user_id
                           AND c.role='clinic' AND c.clinic_status='approved'
                       ))"""
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
                """SELECT clinic_name AS name, MIN(owner_user_id) AS owner_user_id FROM slots
                   WHERE owner_user_id IS NULL OR owner_user_id IN (
                       SELECT id FROM accounts WHERE role='clinic' AND clinic_status='approved'
                   ) GROUP BY clinic_name
                   UNION
                   SELECT clinic_name AS name, id AS owner_user_id FROM accounts
                   WHERE role='clinic' AND clinic_status='approved'
                   ORDER BY name COLLATE NOCASE"""
            ).fetchall()
            clinics = []
            for row in rows:
                owner = row["owner_user_id"]
                account = connection.execute(
                    "SELECT clinic_address,phone FROM accounts WHERE id=?", (owner,)
                ).fetchone() if owner else None
                clinics.append({
                    "id": str(owner or ""), "name": row["name"],
                    "address": account["clinic_address"] if account else "",
                    "phone": account["phone"] if account else "",
                })
        self.send_json(200, clinics)

    # По ID загружаем детали слота перед показом формы подтверждения.
    def get_slot(self, slot_id: int) -> None:
        with connect_db() as connection:
            row = connection.execute(
                """SELECT s.*, EXISTS(
                       SELECT 1 FROM appointments a WHERE a.slot_id = s.id
                   ) AS booked
                   FROM slots s WHERE s.id = ?""",
                (slot_id,),
            ).fetchone()
        if row is None:
            self.send_json(404, {"error": "Время приёма не найдено"})
            return
        if row["owner_user_id"] is not None:
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
        scope = "WHERE s.owner_user_id=?" if account["role"] == "clinic" else ""
        with connect_db() as connection:
            rows = connection.execute(
                f"""SELECT a.id, a.patient_name, a.phone, a.created_at,
                          s.id AS slot_id, s.clinic_name, s.service,
                          s.appointment_date, s.appointment_time, s.price
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
            service = str(data.get("service", "")).strip()
            appointment_date = str(data.get("date", "")).strip()
            appointment_time = str(data.get("time", "")).strip()
            price = int(data.get("price", 0))
            parsed_date = date.fromisoformat(appointment_date)
            parsed_time = datetime.strptime(appointment_time, "%H:%M").time()
            if not clinic_name or not service or datetime.combine(parsed_date, parsed_time) <= datetime.now() or price <= 0:
                raise ValueError
        except (ValueError, TypeError):
            self.send_json(400, {"error": "Проверьте услугу, дату, время и цену"})
            return

        try:
            with connect_db() as connection:
                cursor = connection.execute(
                    """INSERT INTO slots
                       (clinic_name, service, appointment_date, appointment_time, price, owner_user_id)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (clinic_name, service, appointment_date, appointment_time, price, account["id"]),
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
                "SELECT EXISTS(SELECT 1 FROM appointments WHERE slot_id = ?)", (slot_id,)
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
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "Это время уже заняли. Выберите другое."})
            return

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
        file_path = (WEB_ROOT / relative_path).resolve()
        if WEB_ROOT.resolve() not in file_path.parents or not file_path.is_file():
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
