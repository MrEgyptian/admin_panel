from datetime import date, datetime
from typing import Optional


_ISO_DATETIME_FORMATS = (
	"%Y-%m-%dT%H:%M:%S",
	"%Y-%m-%dT%H:%M",
	"%Y-%m-%d",
)


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
	if not value:
		return None
	sanitized = value.strip()
	if not sanitized:
		return None
	if sanitized.endswith("Z"):
		sanitized = sanitized[:-1]
	for pattern in _ISO_DATETIME_FORMATS:
		try:
			return datetime.strptime(sanitized, pattern)
		except ValueError:
			continue
	return None


def format_timestamp(value: datetime) -> str:
	return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%S")


def humanize_timestamp(value: datetime) -> str:
	return value.strftime("%Y-%m-%d %H:%M")

