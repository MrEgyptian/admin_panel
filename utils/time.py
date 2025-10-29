
from typing import Optional

from datetime import datetime, date
def parse_form_date(value: str) -> Optional[str]:
	if not value:
		return None
	try:
		parsed_date = datetime.strptime(value, "%Y-%m-%d").date()
	except ValueError:
		return None
	return parsed_date.isoformat()


def parse_iso_date(value: Optional[str]) -> Optional[date]:
	if not value:
		return None
	try:
		return datetime.strptime(value, "%Y-%m-%d").date()
	except ValueError:
		return None

