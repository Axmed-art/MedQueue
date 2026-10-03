"""Local MedQueue server and SQLite API."""

from __future__ import annotations

import json
import mimetypes
import re
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "MedQueue"
DATABASE = ROOT / "medqueue.db"
HOST = "127.0.0.1"
PORT = 8000


@contextmanager
def connect_db() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    is_new_database = not DATABASE.exists()
    with connect_db() as connection:
        connection.executescript(
            """
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

            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slot_id INTEGER NOT NULL UNIQUE REFERENCES slots(id) ON DELETE RESTRICT,
                patient_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

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

    def log_message(self, format: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")

    def send_json(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

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

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/api/slots":
            self.get_slots(parse_qs(parsed.query))
        elif re.fullmatch(r"/api/slots/\d+", path):
            self.get_slot(int(path.rsplit("/", 1)[1]))
        elif path == "/api/appointments":
            self.get_appointments()
        else:
            self.serve_static(path)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path.rstrip("/")
        if path == "/api/slots":
            self.create_slot()
        elif path == "/api/appointments":
            self.create_appointment()
        else:
            self.send_json(404, {"error": "Маршрут не найден"})

    def do_DELETE(self) -> None:
        path = urlsplit(self.path).path.rstrip("/")
        match = re.fullmatch(r"/api/slots/(\d+)", path)
        if match:
            self.delete_slot(int(match.group(1)))
        else:
            self.send_json(404, {"error": "Маршрут не найден"})

    def get_slots(self, query: dict[str, list[str]]) -> None:
        include_booked = query.get("all", ["0"])[0] == "1"
        sql = """
            SELECT s.*, EXISTS(
                SELECT 1 FROM appointments a WHERE a.slot_id = s.id
            ) AS booked
            FROM slots s
        """
        params: list = []
        if not include_booked:
            sql += " WHERE NOT EXISTS (SELECT 1 FROM appointments a WHERE a.slot_id = s.id)"
        sql += " ORDER BY s.appointment_date, s.appointment_time"
        with connect_db() as connection:
            rows = connection.execute(sql, params).fetchall()
        self.send_json(200, [slot_record(row, bool(row["booked"])) for row in rows])

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
        self.send_json(200, slot_record(row, bool(row["booked"])))

    def get_appointments(self) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT a.id, a.patient_name, a.phone, a.created_at,
                          s.id AS slot_id, s.clinic_name, s.service,
                          s.appointment_date, s.appointment_time, s.price
                   FROM appointments a JOIN slots s ON s.id = a.slot_id
                   ORDER BY s.appointment_date, s.appointment_time"""
            ).fetchall()
        self.send_json(
            200,
            [
                {
                    "id": row["id"],
                    "patient_name": row["patient_name"],
                    "phone": row["phone"],
                    "created_at": row["created_at"],
                    "slot": {
                        "id": row["slot_id"],
                        "clinic_name": row["clinic_name"],
                        "service": row["service"],
                        "date": row["appointment_date"],
                        "time": row["appointment_time"],
                        "price": row["price"],
                    },
                }
                for row in rows
            ],
        )

    def create_slot(self) -> None:
        try:
            data = self.read_json()
            clinic_name = str(data.get("clinic_name", "Smile Clinic")).strip()
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
                       (clinic_name, service, appointment_date, appointment_time, price)
                       VALUES (?, ?, ?, ?, ?)""",
                    (clinic_name, service, appointment_date, appointment_time, price),
                )
                slot_id = cursor.lastrowid
                row = connection.execute("SELECT * FROM slots WHERE id = ?", (slot_id,)).fetchone()
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "На это время уже создан слот"})
            return
        self.send_json(201, slot_record(row))

    def delete_slot(self, slot_id: int) -> None:
        with connect_db() as connection:
            row = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM appointments WHERE slot_id = ?)", (slot_id,)
            ).fetchone()
            exists = connection.execute("SELECT 1 FROM slots WHERE id = ?", (slot_id,)).fetchone()
            if exists is None:
                self.send_json(404, {"error": "Слот не найден"})
                return
            if row[0]:
                self.send_json(409, {"error": "Нельзя удалить слот с записью пациента"})
                return
            connection.execute("DELETE FROM slots WHERE id = ?", (slot_id,))
        self.send_json(200, {"deleted": True})

    def create_appointment(self) -> None:
        try:
            data = self.read_json()
            patient_name = str(data.get("name", "")).strip()
            phone = str(data.get("phone", "")).strip()
            slot_id = int(data.get("slot_id", 0))
            digits = re.sub(r"\D", "", phone)
            if not patient_name or len(patient_name) > 100 or len(digits) < 7 or len(phone) > 30:
                raise ValueError
            if slot_id <= 0:
                raise ValueError
        except (ValueError, TypeError):
            self.send_json(400, {"error": "Введите имя, корректный телефон и выберите время"})
            return

        try:
            with connect_db() as connection:
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
                cursor = connection.execute(
                    "INSERT INTO appointments (slot_id, patient_name, phone) VALUES (?, ?, ?)",
                    (slot_id, patient_name, phone),
                )
                appointment_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "Это время уже заняли. Выберите другое."})
            return

        self.send_json(
            201,
            {
                "id": appointment_id,
                "patient_name": patient_name,
                "phone": phone,
                "slot": slot_record(slot),
            },
        )

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
    initialize_database()
    httpd = ThreadingHTTPServer((HOST, PORT), MedQueueHandler)
    print(f"MedQueue запущен: http://{HOST}:{PORT}")
    print(f"SQLite база: {DATABASE}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
    finally:
        httpd.server_close()
