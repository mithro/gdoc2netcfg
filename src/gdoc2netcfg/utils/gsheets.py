"""Shared Google Sheets client construction.

OAuth2: provide credentials_file (client_secret.json from Google Cloud
        Console).  Token is cached to token_cache and auto-refreshed on
        expiry.
Service account: provide service_account_file instead.

Credentials live in the [sheets] section of gdoc2netcfg.toml
(SheetsConfig).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.config import SheetsConfig


_SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def get_gspread_client(sheets_config: SheetsConfig) -> object:
    """Return an authenticated gspread Client.

    Tries service_account_file first (non-interactive), then OAuth2
    (opens a browser on first use; token is cached for subsequent runs).
    """
    try:
        import gspread
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
    except ImportError as exc:
        raise RuntimeError(
            "Google Sheets dependencies not installed. "
            "Install with: uv sync  (gspread and google-auth-oauthlib are in pyproject.toml)"
        ) from exc

    if sheets_config.service_account_file:
        sa_path = Path(sheets_config.service_account_file).expanduser()
        if not sa_path.exists():
            raise RuntimeError(
                f"Service account file not found: {sa_path}"
            )
        from google.oauth2.service_account import Credentials as SACredentials
        creds = SACredentials.from_service_account_file(str(sa_path), scopes=_SCOPES)
        return gspread.Client(auth=creds)

    credentials_file = sheets_config.credentials_file
    if not credentials_file:
        raise RuntimeError(
            "No credentials_file or service_account_file configured in "
            "[sheets] section of gdoc2netcfg.toml"
        )

    creds_path = Path(credentials_file).expanduser()
    if not creds_path.exists():
        raise RuntimeError(
            f"OAuth2 credentials file not found: {creds_path}\n"
            "Download it from Google Cloud Console → APIs & Services → Credentials"
        )

    token_path = Path(sheets_config.token_cache).expanduser()

    creds: Credentials | None = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), _SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            from google_auth_oauthlib.flow import InstalledAppFlow
            flow = InstalledAppFlow.from_client_secrets_file(str(creds_path), _SCOPES)
            creds = flow.run_local_server(port=0)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json())

    return gspread.Client(auth=creds)
