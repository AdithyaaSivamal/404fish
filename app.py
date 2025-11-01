# app.py

import asyncio
import logging
import os
import sys
import time
import json
import socket
from datetime import datetime, timezone
from typing import List, Optional

import asyncpg
import geoip2.database
from aiobotocore.session import get_session
from fastapi import FastAPI, HTTPException
from fastapi.responses import (
    FileResponse,
    Response,
)  # <-- Make sure Response is imported
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# --- Configs ---
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

CW_LOG_GROUPS_JSON = os.environ.get("CW_LOG_GROUPS_JSON", "[]")
try:
    LOG_GROUPS_TO_POLL = json.loads(CW_LOG_GROUPS_JSON)
except json.JSONDecodeError:
    logging.error("Invalid JSON in CW_LOG_GROUPS_JSON env var. Exiting.")
    sys.exit(1)

GEOIP_CITY_DB_PATH = os.environ.get("GEOIP_DB_PATH", "/app/GeoLite2-City.mmdb")
GEOIP_ASN_DB_PATH = "/app/GeoLite2-ASN.mmdb"
DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT", 5432)
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
KEYWORD_FILE_PATH = "/app/suspicious_keywords.txt"

SUSPICIOUS_KEYWORDS = set()


def load_suspicious_keywords():
    try:
        with open(KEYWORD_FILE_PATH, "r") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    SUSPICIOUS_KEYWORDS.add(line)
        logging.info(f"Loaded {len(SUSPICIOUS_KEYWORDS)} suspicious keywords.")
    except FileNotFoundError:
        logging.warning(
            f"Keyword file not found at {KEYWORD_FILE_PATH}. No hostnames will be auto-flagged."
        )
    except Exception as e:
        logging.error(f"Error loading keyword file: {e}")


last_poll_times_ms = {
    group["name"]: int((time.time() - 900) * 1000) for group in LOG_GROUPS_TO_POLL
}

# --- Initialize Application and Clients ---
app = FastAPI()
aio_session = get_session()
db_pool = None

try:
    geoip_city_reader = geoip2.database.Reader(GEOIP_CITY_DB_PATH)
except Exception:
    logging.error(f"GeoIP City DB not found at {GEOIP_CITY_DB_PATH}.")
    geoip_city_reader = None

try:
    geoip_asn_reader = geoip2.database.Reader(GEOIP_ASN_DB_PATH)
except Exception:
    logging.error(f"GeoIP ASN DB not found at {GEOIP_ASN_DB_PATH}.")
    geoip_asn_reader = None


# --- Pydantic Data Models ---
class RecentEvent(BaseModel):
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_port: int
    city: Optional[str] = None
    country: Optional[str] = None
    hostname: Optional[str] = None
    isp: Optional[str] = None
    is_suspicious: bool


class MapDataPoint(BaseModel):
    city: Optional[str] = None
    country: Optional[str] = None
    latitude: float
    longitude: float
    attempt_count: int


class StatusResponse(BaseModel):
    status: str
    message: str


# --- Database Functions ---
async def get_db_pool():
    if not all([DB_HOST, DB_NAME, DB_USER, DB_PASSWORD]):
        logging.error("Database environment variables not fully set. Retrying...")
        return None
    try:
        pool = await asyncpg.create_pool(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            timeout=10,
        )
        return pool
    except Exception as e:
        logging.error(f"Database connection pool failed: {e}. Retrying...")
        return None


async def init_db():
    global db_pool
    retry_delay = 5
    while db_pool is None:
        db_pool = await get_db_pool()
        if db_pool:
            logging.info("Database pool created successfully.")
            break
        logging.warning(f"DB connection failed. Retrying in {retry_delay} seconds...")
        await asyncio.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, 60)

    create_table_sql = """
    CREATE TABLE IF NOT EXISTS flow_log_events (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP WITH TIME ZONE,
        src_ip VARCHAR(45),
        src_port INT,
        dst_port INT,
        action VARCHAR(6),
        city VARCHAR(100),
        country VARCHAR(100),
        latitude REAL,
        longitude REAL,
        hostname VARCHAR(255),
        isp VARCHAR(255),
        is_suspicious BOOLEAN DEFAULT false,
        UNIQUE(src_ip, timestamp, dst_port)
    );
    """
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(create_table_sql)
        logging.info(
            "Database initialized successfully. 'flow_log_events' table checked/created."
        )
    except asyncpg.exceptions.PostgresError as e:
        logging.error(f"Error creating database table: {e}")
        db_pool = None


# --- Background Log Processor ---


def get_rdns_sync(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except Exception:
        return "N/A"


def get_enrichment_data_sync(ip_address):
    data = {
        "city": None,
        "country": None,
        "latitude": None,
        "longitude": None,
        "isp": None,
    }
    if geoip_city_reader:
        try:
            response = geoip_city_reader.city(ip_address)
            data.update(
                {
                    "city": response.city.name,
                    "country": response.country.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                }
            )
        except Exception:
            pass
    if geoip_asn_reader:
        try:
            response = geoip_asn_reader.asn(ip_address)
            data["isp"] = response.autonomous_system_organization
        except Exception:
            pass
    return data


def check_event_suspicious(hostname: str, isp: str) -> bool:
    """Checks if the event's hostname or ISP contains any suspicious keywords."""

    # Check hostname
    if hostname and hostname != "N/A":
        hostname_lower = hostname.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in hostname_lower:
                return True

    # Check ISP
    if isp and isp != "N/A":
        isp_lower = isp.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in isp_lower:
                return True

    return False


async def process_flow_logs_for_group(log_group_info):
    log_group_name = log_group_info["name"]
    region = log_group_info["region"]
    last_poll_time = last_poll_times_ms.get(
        log_group_name, int((time.time() - 900) * 1000)
    )
    current_time_ms = int(time.time() * 1000)

    logging.info(
        f"Polling {log_group_name} in {region} from {last_poll_time} to {current_time_ms}"
    )

    events_to_insert = []
    try:
        async with aio_session.create_client("logs", region_name=region) as logs_client:
            response = await logs_client.filter_log_events(
                logGroupName=log_group_name,
                startTime=last_poll_time + 1,
                endTime=current_time_ms,
            )

        parsed_event_count = 0
        for event in response.get("events", []):
            message = event.get("message", "")
            parts = message.split(" ")
            parsed_event_count += 1

            if len(parts) < 14 or parts[12] not in ("ACCEPT", "REJECT"):
                continue

            try:
                if parts[12] == "REJECT":
                    src_ip = parts[3]
                    src_port = int(parts[5])
                    dst_port = int(parts[6])
                    timestamp_unix = int(parts[10])

                    geo_task = asyncio.to_thread(get_enrichment_data_sync, src_ip)
                    rdns_task = asyncio.to_thread(get_rdns_sync, src_ip)
                    geo_data, hostname = await asyncio.gather(geo_task, rdns_task)

                    is_suspicious = check_event_suspicious(hostname, geo_data["isp"])

                    event_data = (
                        datetime.fromtimestamp(timestamp_unix, tz=timezone.utc),
                        src_ip,
                        src_port,
                        dst_port,
                        "REJECT",
                        geo_data["city"],
                        geo_data["country"],
                        geo_data["latitude"],
                        geo_data["longitude"],
                        hostname,
                        geo_data["isp"],
                        is_suspicious,
                    )
                    events_to_insert.append(event_data)
            except (ValueError, IndexError) as e:
                logging.warning(f"Failed to parse log line: {message}. Error: {e}")

        logging.info(
            f"Parsed {parsed_event_count} log events. Found {len(events_to_insert)} REJECT events."
        )

        if events_to_insert:
            async with db_pool.acquire() as conn:
                insert_query = """
                INSERT INTO flow_log_events
                (timestamp, src_ip, src_port, dst_port, action, city, country,
                 latitude, longitude, hostname, isp, is_suspicious)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (src_ip, timestamp, dst_port) DO NOTHING
                """
                await conn.executemany(insert_query, events_to_insert)
            logging.info(
                f"Successfully inserted {len(events_to_insert)} events from {log_group_name} into DB."
            )

        last_poll_times_ms[log_group_name] = current_time_ms

    except Exception as e:
        logging.error(f"Error during log processing for {log_group_name}: {e}")


async def run_log_processor():
    while db_pool is None:
        logging.warning("Log processor: DB pool not ready, waiting 10s...")
        await asyncio.sleep(10)
    logging.info(
        f"Log processor: DB pool is ready. Starting polling loop for {len(LOG_GROUPS_TO_POLL)} log group(s)."
    )
    while True:
        try:
            tasks = []
            for group_info in LOG_GROUPS_TO_POLL:
                tasks.append(process_flow_logs_for_group(group_info))
            await asyncio.gather(*tasks)
        except Exception as e:
            logging.error(f"Unhandled exception in log processor loop: {e}")
        await asyncio.sleep(60)


@app.on_event("startup")
async def on_startup():
    logging.info("Application starting up...")
    load_suspicious_keywords()
    asyncio.create_task(init_db())
    asyncio.create_task(run_log_processor())


# --- API Endpoints ---


@app.get("/api/recent-events", response_model=List[RecentEvent])
async def get_recent_events():
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not yet connected")
    try:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT timestamp, src_ip, src_port, dst_port, city, country, hostname, isp, is_suspicious
                FROM flow_log_events
                WHERE is_suspicious = false
                ORDER BY timestamp DESC
                LIMIT 50
                """
            )
            return [dict(row) for row in rows]
    except asyncpg.exceptions.PostgresError as e:
        logging.error(f"API /recent-events error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch recent events")


@app.get("/api/map-data", response_model=List[MapDataPoint])
async def get_map_data():
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not yet connected")
    try:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT city, country, latitude, longitude, COUNT(*) as attempt_count
                FROM flow_log_events
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL AND timestamp >= NOW() - INTERVAL '1 hour'
                GROUP BY city, country, latitude, longitude
                """
            )
            return [dict(row) for row in rows]
    except asyncpg.exceptions.PostgresError as e:
        logging.error(f"API /map-data error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch map data")


@app.get("/api/events-by-location", response_model=List[RecentEvent])
async def get_events_by_location(
    city: Optional[str] = None, country: Optional[str] = None
):
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not yet connected")

    query_params = []
    where_clauses = ["timestamp >= NOW() - INTERVAL '1 hour'"]

    if city:
        query_params.append(city)
        where_clauses.append(f"city = ${len(query_params)}")
    elif country:
        query_params.append(country)
        where_clauses.append(f"country = ${len(query_params)}")
    else:
        where_clauses.append("city IS NULL AND country IS NULL")

    query = f"""
        SELECT timestamp, src_ip, src_port, dst_port, city, country, hostname, isp, is_suspicious
        FROM flow_log_events
        WHERE {" AND ".join(where_clauses)}
        ORDER BY timestamp DESC LIMIT 200
    """

    try:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(query, *query_params)
            return [dict(row) for row in rows]
    except asyncpg.exceptions.PostgresError as e:
        logging.error(f"API /events-by-location error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch location data")


@app.get("/api/flagged-events", response_model=List[RecentEvent])
async def get_flagged_events():
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not yet connected")
    try:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT timestamp, src_ip, src_port, dst_port, city, country, hostname, isp, is_suspicious
                FROM flow_log_events
                WHERE is_suspicious = true
                ORDER BY timestamp DESC
                LIMIT 100
                """
            )
            return [dict(row) for row in rows]
    except asyncpg.exceptions.PostgresError as e:
        logging.error(f"API /flagged-events error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch flagged events")


@app.put("/api/flag-ip/{ip_address}", response_model=StatusResponse)
async def flag_ip(ip_address: str):
    """
    Manually flags an IP address as suspicious in the database.
    """
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not yet. connected")

    try:
        async with db_pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE flow_log_events
                SET is_suspicious = true
                WHERE src_ip = $1
                """,
                ip_address,
            )

        if result == "UPDATE 0":
            logging.warning(
                f"Attempted to flag IP {ip_address}, but it was not found in the table."
            )
            return {
                "status": "success",
                "message": f"IP {ip_address} not found in recent logs, but command accepted.",
            }

        logging.info(f"Manually flagged IP: {ip_address}")
        return {"status": "success", "message": f"IP {ip_address} has been flagged."}

    except asyncpg.exceptions.PostgresError as e:
        logging.error(f"API /flag-ip error: {e}")
        raise HTTPException(status_code=500, detail="Failed to flag IP.")


# --- Serve Frontend ---


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    # Return a 204 No Content response to stop the browser from logging an error
    return Response(status_code=204)


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
async def read_index():
    """Serves the main index.html file."""
    return FileResponse("static/index.html")
