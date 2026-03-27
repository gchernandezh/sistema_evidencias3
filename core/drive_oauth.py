# core/drive_oauth.py
from __future__ import annotations
import io, json, mimetypes
from typing import Dict, Optional
from django.conf import settings
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google.oauth2.credentials import Credentials
from django.db import connection
from google.auth.transport.requests import Request

def _load_creds() -> Credentials:
    with connection.cursor() as cur:
        cur.execute("SELECT token_json FROM drive_oauth_token WHERE id=1")
        row = cur.fetchone()
    if not row or not row[0]:
        raise RuntimeError("Falta token OAuth. Visita /drive/auth para autorizar Google Drive.")
    data = json.loads(row[0])
    return Credentials.from_authorized_user_info(data, scopes=settings.DRIVE_SCOPES)

def save_creds(creds: Credentials, owner_email: str | None = None) -> None:
    data = creds.to_json()
    with connection.cursor() as cur:
        cur.execute("""
            INSERT INTO drive_oauth_token (id, token_json, owner_email, updated_at)
            VALUES (1, %s, %s, now())
            ON CONFLICT (id) DO UPDATE
            SET token_json = EXCLUDED.token_json,
                owner_email = COALESCE(EXCLUDED.owner_email, drive_oauth_token.owner_email),
                updated_at = now()
        """, [data, owner_email])

def get_service():
    creds = _load_creds()
    return build("drive", "v3", credentials=creds, cache_discovery=False)

def ensure_child_folder(parent_id: str, name: str) -> str:
    svc = get_service()
    q = f"'{parent_id}' in parents and name = '{name}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    res = svc.files().list(q=q, fields="files(id,name)", pageSize=1).execute()
    files = res.get("files", [])
    if files:
        return files[0]["id"]
    meta = {
        "name": name,
        "parents": [parent_id],
        "mimeType": "application/vnd.google-apps.folder",
    }
    created = svc.files().create(body=meta, fields="id").execute()
    return created["id"]

def upload_file(folder_id: str, django_file, filename: str) -> dict:
    from googleapiclient.http import MediaIoBaseUpload
    import io
    svc = get_service()
    django_file.seek(0)
    media = MediaIoBaseUpload(io.BytesIO(django_file.read()), mimetype=django_file.content_type, resumable=False)
    meta = {"name": filename, "parents": [folder_id]}
    return svc.files().create(body=meta, media_body=media, fields="id,webViewLink").execute()

def delete_file(file_id: str):
    if not file_id:
        return
    svc = get_service()
    try:
        svc.files().delete(fileId=file_id).execute()
    except Exception:
        pass
