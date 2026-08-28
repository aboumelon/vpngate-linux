from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address
from io import StringIO

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


EXPECTED_COLUMNS = (
    "HostName",
    "IP",
    "Score",
    "Ping",
    "Speed",
    "CountryLong",
    "CountryShort",
    "NumVpnSessions",
    "Uptime",
    "TotalUsers",
    "TotalTraffic",
    "LogType",
    "Operator",
    "Message",
    "OpenVPN_ConfigData_Base64",
)


class ServerRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    hostname: str = Field(min_length=1)
    ip: IPv4Address
    score: int = Field(ge=0)
    ping_ms: int = Field(ge=0)
    speed_bps: int = Field(ge=0)
    country_long: str = Field(min_length=1)
    country_short: str = Field(min_length=2, max_length=2)
    sessions: int = Field(ge=0)
    uptime_ms: int = Field(ge=0)
    total_users: int = Field(ge=0)
    total_traffic_bytes: int = Field(ge=0)
    log_type: str
    operator: str
    message: str

    @field_validator("ip")
    @classmethod
    def validate_public_ip(cls, value: IPv4Address) -> IPv4Address:
        if not value.is_global:
            raise ValueError("Server IP must be public")
        return value

    @property
    def speed_mbps(self) -> float:
        return self.speed_bps / 1_000_000

    @property
    def uptime_days(self) -> float:
        return self.uptime_ms / 86_400_000


class ServerCache(BaseModel):
    model_config = ConfigDict(frozen=True)

    fetched_at: datetime
    source_url: str
    rejected_rows: int = Field(ge=0)
    servers: tuple[ServerRecord, ...]


@dataclass(frozen=True)
class ParseResult:
    servers: tuple[ServerRecord, ...]
    rejected_rows: int


def _record_from_row(row: dict[str, str]) -> ServerRecord:
    return ServerRecord(
        hostname=row["HostName"].strip(),
        ip=row["IP"].strip(),
        score=row["Score"],
        ping_ms=row["Ping"],
        speed_bps=row["Speed"],
        country_long=row["CountryLong"].strip(),
        country_short=row["CountryShort"].strip().upper(),
        sessions=row["NumVpnSessions"],
        uptime_ms=row["Uptime"],
        total_users=row["TotalUsers"],
        total_traffic_bytes=row["TotalTraffic"],
        log_type=row["LogType"].strip(),
        operator=row["Operator"].strip(),
        message=row["Message"].strip(),
    )


def parse_server_csv(payload: str) -> ParseResult:
    lines = payload.lstrip("\ufeff").splitlines()
    try:
        header_index = next(
            index for index, line in enumerate(lines) if line.startswith("#HostName,")
        )
    except StopIteration as error:
        raise ValueError("VPN Gate CSV header was not found") from error

    header = lines[header_index].removeprefix("#")
    columns = tuple(next(csv.reader((header,))))
    if columns != EXPECTED_COLUMNS:
        raise ValueError("VPN Gate CSV columns do not match the expected schema")

    data_lines = []
    for line in lines[header_index + 1 :]:
        if line.strip() == "*":
            break
        if line.strip():
            data_lines.append(line)

    reader = csv.DictReader(StringIO("\n".join((header, *data_lines))))
    servers = []
    rejected_rows = 0
    for row in reader:
        try:
            servers.append(_record_from_row(row))
        except (KeyError, TypeError, ValidationError, ValueError):
            rejected_rows += 1

    if not servers:
        raise ValueError("VPN Gate CSV did not contain any valid servers")
    return ParseResult(tuple(servers), rejected_rows)


def make_cache(source_url: str, result: ParseResult) -> ServerCache:
    return ServerCache(
        fetched_at=datetime.now(UTC),
        source_url=source_url,
        rejected_rows=result.rejected_rows,
        servers=result.servers,
    )
