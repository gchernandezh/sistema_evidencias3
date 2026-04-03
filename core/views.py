# core/views.py
import datetime
from django.shortcuts import render, redirect
from django.http import HttpResponseBadRequest
from django.core import signing
from django.core.mail import send_mail
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.models import AnonymousUser, User
from django.db import connection, transaction
from django.views.decorators.http import require_http_methods
from .models import Docente, VwPendientes
from core.models import Docente  # asegúrate de tener este import
from django.contrib.auth import logout
from itertools import groupby
import unicodedata
import os
import csv, io
from google_auth_oauthlib.flow import Flow
import json
from django.http import HttpResponseForbidden
from core.drive_oauth import get_service
from django.views.decorators.http import require_POST
from django.urls import reverse
from django.views.decorators.http import require_GET
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pathlib import Path
from googleapiclient.errors import HttpError
import logging, traceback
from django.shortcuts import redirect
from core.drive_oauth import save_creds
logger = logging.getLogger(__name__)
# en core/views.py
from core.drive_oauth import get_service, ensure_child_folder, upload_file, delete_file
from django.http import JsonResponse


TOKEN_MAX_AGE = 15 * 60  # 15 mins

def delete_file(file_id: str):
    """Borra un archivo en Drive (ignora si ya no existe)."""
    if not file_id:
        return
    svc = get_service()
    try:
        svc.files().delete(fileId=file_id).execute()
    except Exception:
        # No explotamos si ya no existe / sin permisos, etc.
        pass


def login_view(request):
    # Si ya está logueado **y** tiene identidad de docente, al dashboard
    if request.user.is_authenticated and request.session.get("docente_id"):
        return redirect("docente_dashboard")

    # Si está logueado pero NO hay docente en sesión, salimos para evitar loop
    if request.user.is_authenticated and not request.session.get("docente_id"):
        logout(request)
        try:
            request.session.flush()
        except Exception:
            pass

    # En GET siempre renderiza el formulario
    return render(request, "login.html")

def login_google_only(request):
    # Si YA hay sesión, delega en home para decidir (coord/docente)
    if request.user.is_authenticated:
        return redirect("home")
    # Sin sesión → muestra login (200)
    return render(request, "login.html", status=200)


def drive_auth(request):
    # if not _require_coordinator(request):
    #     return HttpResponseForbidden("Solo coordinadores.")

    import os

    print("EXISTE:", os.path.exists("/tmp/client_secret.json"))

    if os.path.exists("/tmp/client_secret.json"):
        with open("/tmp/client_secret.json") as f:
            print("CONTENIDO:", f.read()[:200])

    flow = Flow.from_client_secrets_file(
        str(settings.GOOGLE_OAUTH_CLIENT_SECRETS_FILE),
        scopes=settings.DRIVE_SCOPES,
        redirect_uri="https://sistema-evidencias3.onrender.com/drive/callback",
    )

    # 🚨 ELIMINAMOS ESTO (ERA EL ERROR)
    # flow.oauth2session.__dict__.update(request.session["flow"])

    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    request.session["drive_oauth_state"] = state
    request.session["code_verifier"] = flow.code_verifier

    print("URL COMPLETA GOOGLE:", auth_url)

    # ✅ SOLO GUARDAMOS EL STATE
    request.session["drive_oauth_state"] = state

    return redirect(auth_url)

def drive_callback(request):
    state = request.session.get("drive_oauth_state")
    code_verifier = request.session.get("code_verifier")
    flow = Flow.from_client_secrets_file(
        str(settings.GOOGLE_OAUTH_CLIENT_SECRETS_FILE),
        scopes=settings.DRIVE_SCOPES,
        redirect_uri="https://sistema-evidencias3.onrender.com/drive/callback",
        state=state,
    )

    flow.fetch_token(
    authorization_response=request.build_absolute_uri(),
    code_verifier=code_verifier
    )

    creds = flow.credentials

    # guarda en BD (opcional: quién autorizó)
    owner_email = (getattr(request.user, "email", "") or "").lower()
    save_creds(creds, owner_email=owner_email)

    messages.success(request, "Google Drive autorizado correctamente.")
    return redirect("coord_panel")

@require_http_methods(["POST"])
def send_magic_link(request):
    email = request.POST.get("email", "").strip().lower()

    # Restringe al dominio institucional
    if not email.endswith("@" + settings.ALLOWED_EMAIL_DOMAIN):
        messages.error(request, f"Usa tu correo institucional (@{settings.ALLOWED_EMAIL_DOMAIN}).")
        return redirect("login")

    docente = Docente.objects.filter(email=email, activo=True).first()
    is_coord = email in settings.COORDINATOR_EMAILS

    # Permite avanzar si es docente ACTIVO o si es coordinador autorizado
    if not docente and not is_coord:
        messages.error(request, "Correo no encontrado o usuario inactivo.")
        return redirect("login")

    # Genera token con email y timestamp
    payload = {"email": email, "ts": datetime.datetime.utcnow().timestamp()}
    token = signing.TimestampSigner(salt="magic").sign_object(payload)
    link = request.build_absolute_uri(f"/auth/verify?token={token}")

    # Nombre para el correo (evita romper si no hay Docente)
    destinatario = docente.nombre if docente else "coordinador/a"

    # En esta fase usamos consola (EMAIL_BACKEND = console)
    from django.core.mail import send_mail
    send_mail(
        subject="Acceso al Sistema de Evidencias",
        message=f"Hola {destinatario}, usa este enlace (válido 15 min): {link}",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
    )

    messages.success(request, "Te enviamos un enlace de acceso (revisa la consola en dev).")
    return redirect("login")

def verify_magic_link(request):
    token = request.GET.get("token")
    if not token:
        return HttpResponseBadRequest("Falta token")

    try:
        data = signing.TimestampSigner(salt="magic").unsign_object(token, max_age=TOKEN_MAX_AGE)
        email = data["email"].strip().lower()
    except signing.BadSignature:
        messages.error(request, "Enlace inválido o vencido.")
        return redirect("login")

    # ¿Es docente activo o coordinador autorizado?
    docente = Docente.objects.filter(email=email, activo=True).first()
    is_coord = email in settings.COORDINATOR_EMAILS

    if not docente and not is_coord:
        messages.error(request, "Usuario no autorizado.")
        return redirect("login")

    # Usuario "sombra" para sesión
    user, _ = User.objects.get_or_create(username=email, defaults={"email": email, "is_active": True})
    login(request, user)

    # Guarda correo para navbar y checks
    request.session["docente_email"] = email

    if docente:
        request.session["docente_id"] = docente.id
        messages.success(request, "Bienvenido/a.")
        return redirect("docente_dashboard")

    # Coordinador (no Docente)
    request.session.pop("docente_id", None)
    messages.success(request, "Bienvenido/a, coordinador/a.")
    return redirect("coord_panel")


def _require_docente(request):
    if not request.user.is_authenticated:
        return None

    email = (request.user.email or "").strip().lower()
    with connection.cursor() as cur:
        cur.execute(
            "SELECT id, COALESCE(nombre,'') FROM docentes WHERE lower(email)=%s LIMIT 1",
            [email],
        )
        row = cur.fetchone()

    if not row:
        messages.error(request, "Tu cuenta no está registrada como docente.")
        logout(request)            # ← evita volver a entrar en la vista y seguir redirigiendo
        return None

    return row[0], row[1]

def _require_coordinator(request):
    if not request.user.is_authenticated:
        return None
    email = (getattr(request.user, "email", "") or "").strip().lower()
    return email if email in [e.strip().lower() for e in settings.COORDINATOR_EMAILS] else None

def docente_dashboard(request):
    # Si no está logueado, al login
    if not request.user.is_authenticated:
        return redirect("login")

    # Asegura que exista docente_email
    docente_email = (getattr(request.user, "email", "") or
                     request.session.get("docente_email", "")).strip().lower()    
   
    ident = _require_docente(request)
    if not ident:
        return redirect("login")
    if isinstance(ident, tuple):
        docente_id, _ = ident      # antes: docente_id, docente_email = ident
    else:
        docente_id = ident

    # 1) Trae requeridos + flags (PIAR/obligatorio)
    pendientes_qs = VwPendientes.objects.raw("""
    SELECT
        row_number() OVER () AS id,
        p.*,
        te.solo_piar AS es_piar,
        eff.obligatorio
    FROM vw_pendientes p
    JOIN tipos_entregable te
         ON te.id = p.tipo_id
    JOIN vw_entregas_requeridas_efectivas eff
         ON eff.curso_id = p.curso_id
        AND eff.tipo_id  = p.tipo_id
    LEFT JOIN rubrica_off ro
         ON ro.curso_id = p.curso_id
        AND ro.tipo_id  = p.tipo_id
    LEFT JOIN entrega_cerrada ec
         ON ec.curso_id = p.curso_id
        AND ec.tipo_id  = p.tipo_id
    WHERE p.docente_id = %s
      AND ro.id IS NULL
      AND (
           te.unico_por_curso IS DISTINCT FROM TRUE
           OR ec.id IS NULL     -- si es ÚNICA y está CERRADA, no se muestra
      )
      AND p.semestre = (SELECT MAX(semestre) FROM reglas_entregas)  -- semestre actual
    ORDER BY p.tipo_nombre, p.fecha_limite ASC, p.curso_nombre
    """, [docente_id])
    base_filas = list(pendientes_qs)

    # 2) Recolectar cursos y tipos PIAR presentes
    cursos_piar = {f.curso_id for f in base_filas if getattr(f, "es_piar", False)}
    tipos_piar  = {f.tipo_id  for f in base_filas if getattr(f, "es_piar", False)}

    # 3) Traer estudiantes PIAR de esos cursos
    piar_por_curso = {}
    if cursos_piar:
        with connection.cursor() as cur:
            cur.execute("""
                SELECT m.curso_id, e.id AS estudiante_id, e.nombre
                FROM matriculas m
                JOIN estudiantes e ON e.id = m.estudiante_id
                WHERE m.es_piar = TRUE AND m.curso_id = ANY(%s)
                ORDER BY e.nombre
            """, [list(cursos_piar)])
            for curso_id, est_id, est_nom in cur.fetchall():
                piar_por_curso.setdefault(curso_id, []).append({"id": est_id, "nombre": est_nom})

    # 4) Traer última entrega por (curso,tipo,estudiante) del docente
    estado_ult = {}
    if cursos_piar and tipos_piar:
        with connection.cursor() as cur:
            cur.execute("""
        SELECT t.curso_id, t.tipo_id, t.estudiante_id, t.estado
        FROM (
          SELECT curso_id, tipo_id, estudiante_id, estado,
                 row_number() OVER (
                   PARTITION BY curso_id, tipo_id, estudiante_id
                   ORDER BY created_at DESC
                 ) AS rn
          FROM entregas
          WHERE docente_id = %s
            AND estudiante_id IS NOT NULL
            AND curso_id = ANY(%s)
            AND tipo_id  = ANY(%s)
        ) AS t
        WHERE t.rn = 1
            """, [docente_id, list(cursos_piar), list(tipos_piar)])
            for curso_id, tipo_id, est_id, estado in cur.fetchall():
                estado_ult[(curso_id, tipo_id, est_id)] = estado

    # 5) Expandir filas: si es PIAR → una fila por estudiante; si no, se deja igual
    filas_expandidas = []
    for f in base_filas:
        if getattr(f, "es_piar", False):
            estudiantes = piar_por_curso.get(f.curso_id, [])
            for est in estudiantes:
                # clonar objeto simple
                g = type("Row", (), {})()
                for attr in f.__dict__:
                    setattr(g, attr, getattr(f, attr))
                g.estudiante_id = est["id"]
                g.estudiante_nombre = est["nombre"]
                g.es_multiple = True
                g.estado_actual = estado_ult.get((f.curso_id, f.tipo_id, est["id"]), "PENDIENTE")
                filas_expandidas.append(g)
        else:
            f.estudiante_id = None
            f.estudiante_nombre = ""
            f.es_multiple = False
            filas_expandidas.append(f)

    # 6) Separar requeridas vs opcionales (reposiciones a opcionales; asesoría sigue en requeridas)
    def _norm(s: str) -> str:
        if not s: return ""
        s = unicodedata.normalize("NFD", s)
        return "".join(ch for ch in s if unicodedata.category(ch) != "Mn").lower()

    def es_reposicion(fila) -> bool:
        name = _norm(getattr(fila, "tipo_nombre", ""))
        return ("reposicion" in name) and ("formato" in name or ("lista" in name and "asistencia" in name))

    requeridas = [r for r in filas_expandidas if getattr(r, "obligatorio", True) and not es_reposicion(r)]
    opcionales = [r for r in filas_expandidas if (not getattr(r, "obligatorio", True)) or es_reposicion(r)]

    # 7) Agrupar por tipo
    def agrupar_por_tipo(items):
        ordenados = sorted(items, key=lambda x: (x.tipo_nombre.lower(), x.curso_nombre, x.grupo, x.estudiante_nombre))
        grupos = []
        for tipo, group in groupby(ordenados, key=lambda x: x.tipo_nombre):
            grupos.append({"tipo": tipo, "items": list(group)})
        return grupos

    # === Historial / Estado de mis entregas (semestre actual) ===
    historial = []
    with connection.cursor() as cur:
        cur.execute("""
            WITH sem AS (
            SELECT MAX(semestre) AS s FROM cursos
            )
            SELECT
                e.id,
                e.created_at,
                e.estado,
                e.comentario,
                e.curso_id,
                c.codigo,
                c.grupo,
                c.nombre AS curso_nombre,
                e.tipo_id,
                te.codigo AS tipo_codigo,
                te.nombre AS tipo_nombre,
                e.estudiante_id,
                es.nombre AS estudiante_nombre
            FROM entregas e
            JOIN cursos c            ON c.id  = e.curso_id
            JOIN sem                 ON c.semestre = sem.s
            JOIN tipos_entregable te ON te.id = e.tipo_id
            LEFT JOIN estudiantes es ON es.id = e.estudiante_id
            WHERE e.docente_id = %s
            ORDER BY e.created_at DESC
            LIMIT 200
        """, [docente_id])
        rows = cur.fetchall()
    
    for (eid, created_at, estado, comentario, curso_id, codigo, grupo, curso_nombre,
        tipo_id, tipo_codigo, tipo_nombre, est_id, est_nombre) in rows:
        historial.append({
            "id": eid,
            "fecha": created_at,
            "estado": estado,
            "comentario": comentario or "",
            "curso_id": curso_id,
            "codigo": codigo,
            "grupo": grupo,
            "curso_nombre": curso_nombre,
            "tipo_id": tipo_id,
            "tipo_codigo": tipo_codigo,
            "tipo_nombre": tipo_nombre,
            "estudiante_id": est_id,
            "estudiante_nombre": est_nombre,
        })
    
    # 🔥 NUEVO: ENTREGAS PARA CORRECCIONES (MOVER AQUÍ)
    with connection.cursor() as cur:
        cur.execute("""
            SELECT e.id,
                   c.nombre AS curso,
                   t.nombre AS tipo,
                   e.file_url,
                   e.drive_file_id
            FROM entregas e
            JOIN cursos c ON e.curso_id = c.id
            JOIN tipos_entregable t ON e.tipo_id = t.id
            WHERE e.docente_id = %s
            ORDER BY e.updated_at DESC
        """, [docente_id])
    
        columnas = [col[0] for col in cur.description]
        entregas = [dict(zip(columnas, fila)) for fila in cur.fetchall()]
                # 🔥 LISTAS SIN DUPLICADOS
        cursos_unicos = sorted(set([e["curso"] for e in entregas]))
        tipos_unicos = sorted(set([e["tipo"] for e in entregas]))

    print("ENTREGAS:", entregas)
    
    # 🔥 AHORA SÍ EL CONTEXT (SIN ERROR)
    context = {
        "grupos_regulares": agrupar_por_tipo(requeridas),
        "grupos_opcionales": agrupar_por_tipo(opcionales),
        "docente_email": docente_email,
        "historial": historial,
        "entregas": entregas,
        "cursos_unicos": cursos_unicos,
        "tipos_unicos": tipos_unicos,
    }
    
    return render(request, "dashboard.html", context)


#@require_http_methods(["POST"])
def subir_entrega(request):
    # Evita 405 si alguien abre /entregar con GET
    if request.method != "POST":
        messages.info(request, "Usa el formulario para subir tus evidencias.")
        return redirect("docente_dashboard")
    try:
        # 0) Autenticación de docente
        ident = _require_docente(request)
        if not ident:
            return redirect("login")
        docente_id, docente_nombre = ident

        # Solo POST
        if request.method != "POST":
            return redirect("docente_dashboard")

        # (opcional en dev) Verifica que Drive esté autorizado
        # if not os.path.exists(settings.GOOGLE_OAUTH_TOKEN_FILE):
        #     messages.error(request, "Repositorio Drive no autorizado. (Coordinación: abrir /drive/auth una vez).")
        #     return redirect("docente_dashboard")

        # 1) Datos del form
        curso_id      = request.POST.get("curso_id")
        tipo_id       = request.POST.get("tipo_id")
        comentario    = request.POST.get("comentario", "").strip()
        estudiante_id = request.POST.get("estudiante_id")  # solo PIAR; puede venir vacío

        if not (curso_id and tipo_id):
            messages.error(request, "Faltan datos de la entrega.")
            return redirect("docente_dashboard")

        # 2) Info del tipo (flags: único / solo_piar)
        with connection.cursor() as cur:
            cur.execute("""
                SELECT codigo, nombre,
                    COALESCE(unico_por_curso, FALSE) AS unico_por_curso,
                    COALESCE(solo_piar,       FALSE) AS solo_piar
                FROM tipos_entregable
                WHERE id = %s
            """, [tipo_id])
            row = cur.fetchone()

        if not row:
            messages.error(request, "Tipo de entregable inexistente.")
            return redirect("docente_dashboard")

        tipo_codigo, tipo_nombre, unico_por_curso, solo_piar = row[0], (row[1] or ""), bool(row[2]), bool(row[3])

        # 3) Si es ÚNICA y está CERRADA por coordinación, bloquear subida
        if unico_por_curso:
            with connection.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM entrega_cerrada
                    WHERE curso_id = %s AND tipo_id = %s
                    LIMIT 1
                """, [curso_id, tipo_id])
                if cur.fetchone():
                    messages.error(request, "Esta entrega única está cerrada por coordinación. Solicita reapertura para poder subir otra vez.")
                    return redirect("docente_dashboard")

        # 4) Archivos (Asesoría permite múltiples -> name="archivos"; resto -> "archivo")
        files = request.FILES.getlist("archivos")
        if not files:
            f = request.FILES.get("archivo")
            if not f:
                messages.error(request, "Debes seleccionar archivo(s).")
                return redirect("docente_dashboard")
            files = [f]

        # 5) Validaciones por archivo (extensión / tamaño)
        allowed = [e.strip().lower() for e in settings.ALLOWED_UPLOAD_EXTS]
        for f in files:
            ext = os.path.splitext(f.name)[1][1:].lower()
            if ext not in allowed:
                messages.error(request, f"Formato no permitido: .{ext}. Permitidos: {', '.join(settings.ALLOWED_UPLOAD_EXTS)}")
                return redirect("docente_dashboard")
            if f.size > settings.MAX_UPLOAD_MB * 1024 * 1024:
                mb = round(f.size / (1024 * 1024), 2)
                messages.error(request, f"Archivo muy grande ({mb} MB). Límite: {settings.MAX_UPLOAD_MB} MB.")
                return redirect("docente_dashboard")

        # 6) Carpeta del curso en Drive
        with connection.cursor() as cur:
            cur.execute("SELECT folder_drive_id FROM cursos WHERE id=%s", [curso_id])
            r = cur.fetchone()
        if not r or not r[0]:
            messages.error(request, "Este curso no tiene carpeta configurada en Drive.")
            return redirect("docente_dashboard")
        curso_folder_id = r[0]

        # 7) Carpeta por tipo; para PIAR, subcarpeta por estudiante
        tipo_folder_id = ensure_child_folder(curso_folder_id, (tipo_nombre or "").upper())
        destino_folder_id = tipo_folder_id

        if solo_piar:
            if not estudiante_id:
                messages.error(request, "Falta seleccionar el estudiante para la evidencia PIAR.")
                return redirect("docente_dashboard")
            with connection.cursor() as cur:
                cur.execute("SELECT nombre FROM estudiantes WHERE id=%s", [estudiante_id])
                rr = cur.fetchone()
            estudiante_nombre = rr[0] if rr else "ESTUDIANTE"
            destino_folder_id = ensure_child_folder(tipo_folder_id, f"PIAR - {estudiante_nombre}")

        # 7.1) REEMPLAZO: si es ÚNICA y NO es PIAR, borra el archivo anterior en Drive (si existía)
        if unico_por_curso and not solo_piar:
            with connection.cursor() as cur:
                cur.execute("""
                    SELECT drive_file_id
                    FROM entregas
                    WHERE curso_id=%s AND tipo_id=%s
                    ORDER BY created_at DESC
                    LIMIT 1
                """, [curso_id, tipo_id])
                prev = cur.fetchone()
            if prev and prev[0]:
                delete_file(prev[0])  # <<-- usa el helper que pegaste arriba

        # 8) SUBIR a Drive e INSERTAR en BD (para Asesoría pueden ser varios)
        ok_count = 0

        for f in files:
            created  = upload_file(destino_folder_id, f, f.name)
            file_id  = created.get("id")
            file_url = f"https://drive.google.com/file/d/{file_id}/view"

            with connection.cursor() as cur, transaction.atomic():

                # 🔍 BUSCAR SI YA EXISTE ENTREGA
                cur.execute("""
                    SELECT id, drive_file_id
                    FROM entregas
                    WHERE curso_id = %s
                    AND docente_id = %s
                    AND tipo_id = %s
                    AND (%s IS NULL OR estudiante_id = %s)
                    ORDER BY created_at DESC
                    LIMIT 1
                """, [curso_id, docente_id, tipo_id, estudiante_id, estudiante_id])

                existente = cur.fetchone()

                if existente:
                    entrega_id, old_drive_id = existente

                    # 🧹 BORRAR ARCHIVO ANTERIOR EN DRIVE
                    if old_drive_id:
                        delete_file(old_drive_id)

                    # 🔄 ACTUALIZAR (REEMPLAZO)
                    cur.execute("""
                        UPDATE entregas
                        SET file_url = %s,
                            drive_file_id = %s,
                            estado = 'EN_REVISION',
                            updated_at = NOW()
                        WHERE id = %s
                    """, [file_url, file_id, entrega_id])

                else:
                    # ➕ INSERTAR NUEVO
                    cur.execute("""
                        INSERT INTO entregas (
                            curso_id, docente_id, tipo_id,
                            comentario, file_url, drive_file_id,
                            estado, estudiante_id
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, 'EN_REVISION', %s)
                    """, [curso_id, docente_id, tipo_id,
                        (comentario or None), file_url, file_id, estudiante_id])

            ok_count += 1

        # 9) (ELIMINADO) NO cerrar automáticamente aquí.
        #    Si más adelante quieres cierre automático al APROBAR, lo hacemos en el flujo de evaluación del coordinador.

        messages.success(request, f"Entrega registrada correctamente en Google Drive ✅ ({ok_count} archivo(s))")
        return redirect("docente_dashboard")
    except Exception as e:
        # imprime stacktrace en Render y muestra mensaje al usuario
        logger.exception("Error en subir_entrega")
        messages.error(request, f"Error al subir: {e}")
        return redirect("docente_dashboard")



def coord_panel(request):
    # 1) Solo coordinadores
    email = (getattr(request.user, "email", "") or "").strip().lower()
    if email not in [e.strip().lower() for e in settings.COORDINATOR_EMAILS]:
        messages.error(request, "Acceso solo para coordinadores.")
        return redirect("home")

    # ------------------------------------------------------------
    # 2) Obtener los IDs de las rúbricas (1° y 2° corte)
    # ------------------------------------------------------------
    with connection.cursor() as cur:
        cur.execute("""
            SELECT id, lower(nombre) AS n
            FROM tipos_entregable
            WHERE nombre ILIKE 'rúbricas de los proyectos%%'
               OR nombre ILIKE 'rubricas de los proyectos%%'
        """)
        rows_r = cur.fetchall()

    rubrica_c1_id, rubrica_c2_id = None, None
    for tid, n in rows_r:
        if '2 corte' in n:
            rubrica_c2_id = tid
        else:
            rubrica_c1_id = tid

    # ------------------------------------------------------------
    # 3) Traer los ENUNCIADOS por código (ENUN1 / ENUN2)
    #    Tomando el más reciente por (curso + corte)
    # ------------------------------------------------------------
    with connection.cursor() as cur:
        cur.execute("""
            SELECT
                c.id                                      AS curso_id,
                c.codigo                                  AS curso_codigo,
                c.grupo                                   AS grupo,
                c.nombre                                  AS curso_nombre,
                (CASE WHEN t.codigo = 'ENUN2' THEN TRUE ELSE FALSE END) AS is_corte2,
                MAX(e.created_at)                         AS fecha
            FROM entregas e
            JOIN tipos_entregable t ON t.id = e.tipo_id
            JOIN cursos c           ON c.id = e.curso_id
            WHERE t.codigo IN ('ENUN1','ENUN2')
            GROUP BY c.id, c.codigo, c.grupo, c.nombre,
                     (CASE WHEN t.codigo = 'ENUN2' THEN TRUE ELSE FALSE END)
            ORDER BY fecha DESC
            LIMIT 200
        """)
        rows = cur.fetchall()

    enunciados = []
    for (curso_id, curso_codigo, grupo, curso_nombre, is_corte2, fecha) in rows:
        # Elegimos la rúbrica correspondiente al corte
        rubrica_tipo_id = rubrica_c2_id if is_corte2 else rubrica_c1_id

        # ¿Está deshabilitada la rúbrica para este curso + ese corte?
        off = False
        if rubrica_tipo_id:
            with connection.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM rubrica_off
                    WHERE curso_id = %s AND tipo_id = %s
                    LIMIT 1
                """, [curso_id, rubrica_tipo_id])
                off = bool(cur.fetchone())

        enunciados.append({
            "curso_id": curso_id,
            "codigo": curso_codigo,
            "grupo": grupo,
            "curso_nombre": curso_nombre,
            "is_corte2": bool(is_corte2),
            "rubrica_tipo_id": rubrica_tipo_id,  # puede ser None si no existe el tipo aún
            "rubrica_off": off,
            "fecha": fecha,
        })

    # Diagnóstico visible (ayuda a confirmar que llegan filas)
    # messages.info(request, f"Enunciados encontrados: {len(enunciados)}")

    # ------------------------------------------------------------
    # 4) (Compatibilidad) Si tu plantilla tiene otro bloque que usa "items",
    #    lo dejamos como lista vacía para que no falle nada.
    # ------------------------------------------------------------
    items = []  # dejámoslo vacío a propósito (tu panel usa "enunciados")

    # ------------------------------------------------------------
    # 5) Render: enviamos el correo, los enunciados y (por compatibilidad) items
    # ------------------------------------------------------------
    ctx = {
        "coordinador_email": email,
        "enunciados": enunciados,
        "items": items,
        # Si tu template usa esto, también puedes exponer los IDs:
        # "rubrica_c1_id": rubrica_c1_id,
        # "rubrica_c2_id": rubrica_c2_id,
    }
    revision_data = coord_revision_data()
    ctx["revision_data"] = revision_data
    docentes_filtro = sorted(set([e["docente"] for e in revision_data]))
    cursos_filtro = sorted(set([e["curso"] for e in revision_data]))
    tipos_filtro = sorted(set([e["tipo"] for e in revision_data]))
    estados_filtro = ["EN_REVISION", "REVISADO", "APROBADO"]

    ctx["docentes_filtro"] = docentes_filtro
    ctx["cursos_filtro"] = cursos_filtro
    ctx["tipos_filtro"] = tipos_filtro
    ctx["estados_filtro"] = estados_filtro    
    # ... arriba ya calculaste enunciados y tienes ctx armado ...
# ctx = {"coordinador_email": email, "enunciados": enunciados, ...}

    with connection.cursor() as cur:
        cur.execute("""
            SELECT ec.curso_id, c.codigo, c.grupo, c.nombre,
                ec.tipo_id, te.nombre AS tipo_nombre,
                ec.created_at
            FROM entrega_cerrada ec
            JOIN cursos c ON c.id = ec.curso_id
            JOIN tipos_entregable te ON te.id = ec.tipo_id
            ORDER BY ec.created_at DESC
            LIMIT 100
        """)
        rows = cur.fetchall()

    cerradas = []
    for (curso_id, codigo, grupo, curso_nombre, tipo_id, tipo_nombre, fecha) in rows:
        cerradas.append({
            "curso_id": curso_id,
            "codigo": codigo,
            "grupo": grupo,
            "curso_nombre": curso_nombre,
            "tipo_id": tipo_id,
            "tipo_nombre": tipo_nombre,
            "fecha": fecha,
        })

    # ctx["cerradas"] = cerradas

    # === Entregas ÚNICAS recientes (para Cerrar/Reabrir) ===
    with connection.cursor() as cur:
        cur.execute("""
            WITH sem AS (SELECT MAX(semestre) AS s FROM cursos)
            SELECT
                c.id          AS curso_id,
                c.codigo      AS curso_codigo,
                c.grupo       AS grupo,
                c.nombre      AS curso_nombre,
                te.id         AS tipo_id,
                te.codigo     AS tipo_codigo,
                te.nombre     AS tipo_nombre,
                MAX(e.created_at) AS fecha,
                (SELECT 1 FROM entrega_cerrada ec
                WHERE ec.curso_id=c.id AND ec.tipo_id=te.id
                LIMIT 1) AS cerrada
            FROM entregas e
            JOIN cursos c            ON c.id  = e.curso_id
            JOIN tipos_entregable te ON te.id = e.tipo_id
            JOIN sem                 ON c.semestre = sem.s
            WHERE te.unico_por_curso = TRUE
            GROUP BY c.id,c.codigo,c.grupo,c.nombre,te.id,te.codigo,te.nombre
            ORDER BY fecha DESC NULLS LAST
            LIMIT 300
        """)
        rows = cur.fetchall()

    unicas = []
    for (curso_id, curso_codigo, grupo, curso_nombre,
        tipo_id, tipo_codigo, tipo_nombre, fecha, cerrada) in rows:
        unicas.append({
            "curso_id": curso_id,
            "codigo": curso_codigo,
            "grupo": grupo,
            "curso_nombre": curso_nombre,
            "tipo_id": tipo_id,
            "tipo_codigo": tipo_codigo,
            "tipo_nombre": tipo_nombre,
            "fecha": fecha,
            "cerrada": bool(cerrada),
        })

    # añade al contexto
    # ctx["unicas"] = unicas
    # 🔥 NUEVO: datos de reportes
    docentes_rep = coord_reportes_data()

    ctx["docentes_rep"] = docentes_rep
    return render(request, "coord.html", ctx)

@require_http_methods(["POST"])
def coord_toggle_rubrica(request):
    if request.user.username not in settings.COORDINATOR_EMAILS:
        return HttpResponseForbidden("Solo coordinadores.")
    if request.method != "POST":
        return redirect("coord_panel")

    curso_id = request.POST.get("curso_id")
    tipo_id  = request.POST.get("tipo_id")   # <- viene del template ya resuelto (c1 o c2)
    accion   = request.POST.get("accion")    # "off" o "on"

    if not (curso_id and tipo_id and accion):
        messages.error(request, "Solicitud incompleta.")
        return redirect("coord_panel")

    with connection.cursor() as cur, transaction.atomic():
        if accion == "off":
            cur.execute("""
                INSERT INTO rubrica_off (curso_id, tipo_id)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
            """, [curso_id, tipo_id])
            messages.success(request, "Rúbrica deshabilitada para el curso.")
        else:
            cur.execute("DELETE FROM rubrica_off WHERE curso_id=%s AND tipo_id=%s",
                        [curso_id, tipo_id])
            messages.success(request, "Rúbrica habilitada para el curso.")

    return redirect("coord_panel")


@require_POST
def coord_toggle_cierre(request):
    # Solo coordinadores
    if request.user.username not in settings.COORDINATOR_EMAILS:
        return HttpResponseForbidden("Solo coordinadores.")

    curso_id = (request.POST.get("curso_id") or "").strip()
    tipo_id  = (request.POST.get("tipo_id")  or "").strip()
    accion   = (request.POST.get("accion")   or "").strip().lower()   # "cerrar"/"abrir" o "close"/"open"

    # Validar IDs
    try:
        curso_id = int(curso_id)
        tipo_id  = int(tipo_id)
    except ValueError:
        messages.error(request, "IDs de curso/tipo inválidos.")
        return redirect("coord_panel")

    if not accion:
        messages.error(request, "Solicitud incompleta (falta 'accion').")
        return redirect("coord_panel")

    # (Opcional) Verificar que el tipo exista y si es único_por_curso
    with connection.cursor() as cur:
        cur.execute("SELECT COALESCE(unico_por_curso, FALSE) FROM tipos_entregable WHERE id=%s", [tipo_id])
        row = cur.fetchone()
    if not row:
        messages.error(request, "Tipo de entregable inexistente.")
        return redirect("coord_panel")
    # Puedes exigir que sea único. Si quieres bloquear, descomenta:
    # if not row[0]:
    #     messages.error(request, "Este tipo no está marcado como 'único por curso'.")
    #     return redirect("coord_panel")

    close_vals = {"cerrar", "close", "off", "deshabilitar", "disable"}
    open_vals  = {"abrir", "open", "on", "habilitar", "enable", "reabrir"}

    with connection.cursor() as cur, transaction.atomic():
        if accion in close_vals:
            cur.execute("""
                INSERT INTO entrega_cerrada (curso_id, tipo_id, motivo)
                VALUES (%s, %s, 'COORDINADOR')
                ON CONFLICT (curso_id, tipo_id) DO NOTHING
            """, [curso_id, tipo_id])
            messages.success(request, "Entrega única CERRADA para ese curso.")
        elif accion in open_vals:
            cur.execute("DELETE FROM entrega_cerrada WHERE curso_id=%s AND tipo_id=%s", [curso_id, tipo_id])
            messages.success(request, "Entrega única REABIERTA para ese curso.")
        else:
            messages.error(request, "Acción no válida. Usa 'cerrar/abrir' o 'close/open'.")

    return redirect("coord_panel")



@require_http_methods(["GET","POST"])
def coord_piar(request):
    # requiere que ya tengas _require_coordinator y COORDINATOR_EMAILS configurado
    email = _require_coordinator(request)
    if not email:
        messages.error(request, "Acceso solo para coordinadores.")
        return redirect("login")

    if request.method == "POST":
        action = request.POST.get("action")
        try:
            with transaction.atomic():
                if action == "add":
                    documento = request.POST.get("documento_id","").strip()
                    nombre    = request.POST.get("nombre","").strip()
                    correo    = request.POST.get("email","").strip().lower()
                    codigo    = request.POST.get("curso_codigo","").strip()
                    grupo     = request.POST.get("grupo","").strip()

                    if not (documento and nombre and codigo and grupo):
                        raise ValueError("Faltan datos obligatorios.")

                    # curso_id
                    with connection.cursor() as cur:
                        cur.execute("SELECT id FROM cursos WHERE codigo=%s AND grupo=%s LIMIT 1", [codigo, grupo])
                        row = cur.fetchone()
                    if not row:
                        raise ValueError(f"Curso {codigo}-{grupo} no existe.")
                    curso_id = row[0]

                    # estudiante (crear si no existe)
                    with connection.cursor() as cur:
                        cur.execute("SELECT id FROM estudiantes WHERE documento_id=%s LIMIT 1", [documento])
                        est = cur.fetchone()
                    if est:
                        estudiante_id = est[0]
                        with connection.cursor() as cur:
                            cur.execute("UPDATE estudiantes SET nombre=%s, email=%s WHERE id=%s",
                                        [nombre, correo or None, estudiante_id])
                    else:
                        with connection.cursor() as cur:
                            cur.execute(
                                "INSERT INTO estudiantes (documento_id, nombre, email) VALUES (%s,%s,%s) RETURNING id",
                                [documento, nombre, correo or None]
                            )
                            estudiante_id = cur.fetchone()[0]

                    # matrícula PIAR (upsert)
                    with connection.cursor() as cur:
                        cur.execute("""
                            INSERT INTO matriculas (estudiante_id, curso_id, es_piar)
                            VALUES (%s,%s,TRUE)
                            ON CONFLICT (estudiante_id, curso_id)
                            DO UPDATE SET es_piar = EXCLUDED.es_piar
                        """, [estudiante_id, curso_id])

                    messages.success(request, f"PIAR matriculado: {nombre} en {codigo}-{grupo}.")

                elif action == "upload":
                    f = request.FILES.get("csv")
                    if not f:
                        raise ValueError("Adjunta un archivo CSV.")
                    text = io.TextIOWrapper(f.file, encoding="utf-8-sig")
                    reader = csv.DictReader(text)

                    total = 0
                    for row in reader:
                        documento = (row.get("documento_id") or row.get("documento") or "").strip()
                        nombre    = (row.get("nombre") or "").strip()
                        correo    = (row.get("email") or "").strip().lower()
                        codigo    = (row.get("curso_codigo") or row.get("codigo_curso") or row.get("curso") or "").strip()
                        grupo     = (row.get("grupo") or "").strip()

                        if not (documento and nombre and codigo and grupo):
                            continue  # fila incompleta: la saltamos

                        # curso_id
                        with connection.cursor() as cur:
                            cur.execute("SELECT id FROM cursos WHERE codigo=%s AND grupo=%s LIMIT 1", [codigo, grupo])
                            r = cur.fetchone()
                        if not r:
                            continue
                        curso_id = r[0]

                        # estudiante (get or create)
                        with connection.cursor() as cur:
                            cur.execute("SELECT id FROM estudiantes WHERE documento_id=%s LIMIT 1", [documento])
                            e = cur.fetchone()
                        if e:
                            estudiante_id = e[0]
                            with connection.cursor() as cur:
                                cur.execute("UPDATE estudiantes SET nombre=%s, email=%s WHERE id=%s",
                                            [nombre, correo or None, estudiante_id])
                        else:
                            with connection.cursor() as cur:
                                cur.execute(
                                    "INSERT INTO estudiantes (documento_id, nombre, email) VALUES (%s,%s,%s) RETURNING id",
                                    [documento, nombre, correo or None]
                                )
                                estudiante_id = cur.fetchone()[0]

                        # matrícula PIAR (upsert)
                        with connection.cursor() as cur:
                            cur.execute("""
                                INSERT INTO matriculas (estudiante_id, curso_id, es_piar)
                                VALUES (%s,%s,TRUE)
                                ON CONFLICT (estudiante_id, curso_id)
                                DO UPDATE SET es_piar = EXCLUDED.es_piar
                            """, [estudiante_id, curso_id])

                        total += 1

                    messages.success(request, f"CSV procesado. {total} PIAR(s) matriculados/actualizados.")

                elif action == "delete":
                    mid = request.POST.get("matricula_id")
                    with connection.cursor() as cur:
                        cur.execute("DELETE FROM matriculas WHERE id=%s", [mid])
                    messages.success(request, "Matrícula PIAR eliminada.")
        except Exception as e:
            messages.error(request, f"Error: {e}")

    # Listado actual de PIAR
    with connection.cursor() as cur:
        cur.execute("""
            SELECT m.id, c.codigo, c.nombre, c.grupo, e.documento_id, e.nombre, e.email
            FROM matriculas m
            JOIN cursos c ON c.id = m.curso_id
            JOIN estudiantes e ON e.id = m.estudiante_id
            WHERE m.es_piar = TRUE
            ORDER BY c.codigo, c.grupo, e.nombre
        """)
        items = cur.fetchall()

    return render(request, "coord_piar.html", {
        "coordinador_email": request.session.get("docente_email"),
        "items": items,
    })



@require_http_methods(["GET"])
def coord_piar_avance(request):
    email = _require_coordinator(request)
    if not email:
        messages.error(request, "Acceso solo para coordinadores.")
        return redirect("login")

    codigo = (request.GET.get("codigo") or "").strip()
    grupo  = (request.GET.get("grupo")  or "").strip()

    # Cursos con PIAR (para el selector)
    with connection.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT c.id, c.codigo, c.nombre, c.grupo
            FROM matriculas m
            JOIN cursos c ON c.id = m.curso_id
            WHERE m.es_piar = TRUE
            ORDER BY c.codigo, c.grupo
        """)
        cursos = cur.fetchall()  # [(id,codigo,nombre,grupo),...]

    # Reporte por estudiante (última entrega y estado)
    with connection.cursor() as cur:
        cur.execute("""
            WITH tipos AS (
              SELECT id FROM tipos_entregable WHERE solo_piar = TRUE
            ),
            piar AS (
              SELECT m.curso_id, e.id AS estudiante_id, e.nombre, e.email
              FROM matriculas m
              JOIN estudiantes e ON e.id = m.estudiante_id
              WHERE m.es_piar = TRUE
            ),
            ult AS (
              SELECT e.curso_id, e.tipo_id, e.estudiante_id, e.estado, e.file_url, e.created_at,
                     row_number() OVER (PARTITION BY e.curso_id, e.tipo_id, e.estudiante_id ORDER BY e.created_at DESC) rn
              FROM entregas e
              WHERE e.tipo_id IN (SELECT id FROM tipos)
            ),
            req AS (
              SELECT curso_id, tipo_id, fecha_limite
              FROM vw_entregas_requeridas_efectivas
              WHERE tipo_id IN (SELECT id FROM tipos)
            )
            SELECT c.id, c.codigo, c.nombre, c.grupo,
                   p.estudiante_id, p.nombre AS estudiante_nombre, p.email,
                   COALESCE(u.estado::text, 'PENDIENTE') AS estado,
                   u.file_url, u.created_at, r.fecha_limite
            FROM piar p
            JOIN cursos c ON c.id = p.curso_id
            LEFT JOIN req r ON r.curso_id = c.id
            LEFT JOIN ult u ON u.curso_id = c.id AND u.estudiante_id = p.estudiante_id AND u.rn = 1
            WHERE (%s = '' OR c.codigo = %s)
              AND (%s = '' OR c.grupo  = %s)
            ORDER BY c.codigo, c.grupo, estudiante_nombre;
        """, [codigo, codigo, grupo, grupo])
        filas = cur.fetchall()

    # Agrupar por curso para la tabla
    report = {}  # {curso_id: {"curso":..., "items":[...], "resumen":{...}}}
    for (cid, cod, nom, grp, est_id, est_nom, est_mail, estado, file_url, created_at, fecha_limite) in filas:
        curso_key = (cid, cod, nom, grp)
        if cid not in report:
            report[cid] = {
                "curso": {"id": cid, "codigo": cod, "nombre": nom, "grupo": grp, "fecha_limite": fecha_limite},
                "items": [],
                "resumen": {"total": 0, "aprobado": 0, "devuelto": 0, "pendiente": 0, "en_revision": 0}
            }
        report[cid]["items"].append({
            "estudiante_id": est_id,
            "estudiante_nombre": est_nom,
            "email": est_mail,
            "estado": estado,
            "file_url": file_url,
            "created_at": created_at,
        })
        report[cid]["resumen"]["total"] += 1
        key = estado.lower()
        if key in report[cid]["resumen"]:
            report[cid]["resumen"][key] += 1

    # Pasar a lista ordenada
    cursos_rep = [report[k] for k in sorted(report.keys())]

    return render(request, "coord_piar_avance.html", {
        "coordinador_email": email,
        "cursos_selector": cursos,
        "f_codigo": codigo,
        "f_grupo": grupo,
        "cursos_rep": cursos_rep,
    })

@require_GET
def logout_view(request):
    logout(request)
    return redirect("login")


def drive_status(request):
    if not _require_coordinator(request):
        return HttpResponseForbidden("Solo coordinadores.")
    try:
        svc = get_service()
        info = svc.about().get(fields="user/emailAddress, storageQuota/usage, storageQuota/limit").execute()
        email = info["user"]["emailAddress"]
        used = int(info["storageQuota"]["usage"])
        limit = int(info["storageQuota"].get("limit") or 0)
        pct = (used/limit*100) if limit else 0
        messages.success(request, f"Conectado como: {email} | Uso: {used/1024/1024:.1f} MB / {limit/1024/1024:.1f} MB ({pct:.1f}%)")
    except Exception as e:
        messages.error(request, f"Drive no disponible: {e}")
    return redirect("coord_panel")


def home(request):
    """
    NUNCA redirige si el usuario NO está autenticado.
    Devuelve 200 con login.html.
    Si está autenticado, decide a dónde enviarlo.
    """
    if not request.user.is_authenticated:
        # Página de login directa, sin 302.
        return render(request, "login.html", status=200)

    email = (getattr(request.user, "email", "") or "").strip().lower()

    # 1) Coordinador → /coord
    if email in [e.strip().lower() for e in settings.COORDINATOR_EMAILS]:
        return redirect("coord_panel")

    # 2) Docente registrado → dashboard
    with connection.cursor() as cur:
        cur.execute("SELECT id FROM docentes WHERE lower(email)=%s AND activo=TRUE LIMIT 1", [email])
        row = cur.fetchone()
    if row:
        return redirect("docente_dashboard")

    # 3) Otro usuario: muestra login (200) con mensaje, SIN redirigir
    messages.error(request, "Tu cuenta no está registrada como docente.")
    return render(request, "login.html", status=200)

def home_switch(request):
    # 1) No autenticado → Login
    if not request.user.is_authenticated:
        return redirect("login")

    # 2) Email normalizado
    email = (getattr(request.user, "email", "") or "").strip().lower()

    # 3) Coordinador → panel de coordinación
    #    (esto NO se toca: si el correo está en COORDINATOR_EMAILS, va al panel)
    if email in settings.COORDINATOR_EMAILS:
        return redirect("coord_panel")

    # 4) Docente registrado → dashboard
    with connection.cursor() as cur:
        cur.execute(
            "SELECT id FROM docentes WHERE lower(email) = %s LIMIT 1",
            [email],
        )
        row = cur.fetchone()

    if row:
        # Existe en docentes → a su panel
        return redirect("docente_dashboard")

    # 5) No es coordinador ni docente → cerrar sesión y volver a login
    messages.error(request, "Tu cuenta no está registrada como docente.")
    logout(request)  # corta cualquier sesión para evitar bucles 302
    return redirect("login")


def get_service_file():
    token_path = Path(settings.GOOGLE_OAUTH_TOKEN_FILE)
    if not token_path.exists():
        raise FileNotFoundError("No hay token.json (autoriza primero).")
    creds = Credentials.from_authorized_user_info(json.loads(token_path.read_text()))
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def visualizacion_correcciones(request):
    if not request.user.is_authenticated:
        return redirect("login")

    docente_email = (getattr(request.user, "email", "") or "").lower()

    # 🔎 1. Obtener ID del docente
    with connection.cursor() as cur:
        cur.execute("""
            SELECT id
            FROM docentes
            WHERE LOWER(email) = %s
        """, [docente_email])

        row = cur.fetchone()
        docente_id = row[0] if row else None

    if not docente_id:
        messages.error(request, "No se encontró el docente en el sistema.")
        return redirect("dashboard")

    # 🔎 2. Obtener entregas del docente
    with connection.cursor() as cur:
        cur.execute("""
            SELECT e.id,
                   c.nombre AS curso,
                   t.nombre AS tipo,
                   e.file_url,
                   e.curso_id,
                   e.tipo_id,
                   e.drive_file_id
            FROM entregas e
            JOIN cursos c ON e.curso_id = c.id
            JOIN tipos_entregable t ON e.tipo_id = t.id
            WHERE e.docente_id = %s
            ORDER BY e.updated_at DESC
        """, [docente_id])

        columnas = [col[0] for col in cur.description]
        entregas = [dict(zip(columnas, fila)) for fila in cur.fetchall()]

    # 🔄 3. REEMPLAZO DE ARCHIVO
    if request.method == "POST":
        entrega_id = request.POST.get("entrega_id")
        archivo = request.FILES.get("archivo")

        if not archivo:
            messages.error(request, "Debes seleccionar un archivo.")
            return redirect("visualizacion_correcciones")

        with connection.cursor() as cur:
            # 🔎 obtener curso_id y archivo anterior
            cur.execute("""
                SELECT curso_id, drive_file_id
                FROM entregas
                WHERE id = %s AND docente_id = %s
            """, [entrega_id, docente_id])

            row = cur.fetchone()

        if not row:
            messages.error(request, "Entrega no válida.")
            return redirect("visualizacion_correcciones")

        curso_id, old_drive_id = row

        # 🔎 obtener carpeta del curso
        with connection.cursor() as cur:
            cur.execute("""
                SELECT folder_drive_id
                FROM cursos
                WHERE id = %s
            """, [curso_id])

            r = cur.fetchone()

        if not r or not r[0]:
            messages.error(request, "El curso no tiene carpeta en Drive.")
            return redirect("visualizacion_correcciones")

        curso_folder_id = r[0]

        # 🔥 SUBIR ARCHIVO (USANDO TU FUNCIÓN REAL)
        created = upload_file(curso_folder_id, archivo, archivo.name)
        file_id = created.get("id")
        file_url = f"https://drive.google.com/file/d/{file_id}/view"

        with connection.cursor() as cur, transaction.atomic():

            # 🧹 borrar archivo anterior
            if old_drive_id:
                try:
                    delete_file(old_drive_id)
                except Exception:
                    pass

            # 🔄 actualizar registro
            cur.execute("""
                UPDATE entregas
                SET file_url = %s,
                    drive_file_id = %s,
                    estado = 'EN_REVISION',
                    updated_at = NOW()
                WHERE id = %s AND docente_id = %s
            """, [file_url, file_id, entrega_id, docente_id])

        messages.success(request, "Archivo reemplazado correctamente.")
        return redirect("visualizacion_correcciones")

    return render(request, "visualizacion_correcciones.html", {
        "entregas": entregas
    })

def reemplazar_entrega(request):
    if request.method != "POST":
        return JsonResponse({"error": "Método no permitido"}, status=400)

    if not request.user.is_authenticated:
        return JsonResponse({"error": "No autenticado"}, status=403)

    docente_email = request.user.email.lower()

    # 🔎 obtener docente_id
    with connection.cursor() as cur:
        cur.execute("SELECT id FROM docentes WHERE LOWER(email)=%s", [docente_email])
        row = cur.fetchone()

    if not row:
        return JsonResponse({"error": "Docente no encontrado"}, status=404)

    docente_id = row[0]

    entrega_id = request.POST.get("entrega_id")
    archivo = request.FILES.get("archivo")

    if not archivo:
        return JsonResponse({"error": "Archivo requerido"}, status=400)

    # 🔎 obtener datos de entrega
    with connection.cursor() as cur:
        cur.execute("""
            SELECT curso_id, drive_file_id
            FROM entregas
            WHERE id=%s AND docente_id=%s
        """, [entrega_id, docente_id])

        row = cur.fetchone()

    if not row:
        return JsonResponse({"error": "Entrega no válida"}, status=404)

    curso_id, old_drive_id = row

    # 🔎 carpeta de Drive
    with connection.cursor() as cur:
        cur.execute("SELECT folder_drive_id FROM cursos WHERE id=%s", [curso_id])
        r = cur.fetchone()

    if not r or not r[0]:
        return JsonResponse({"error": "Curso sin carpeta en Drive"}, status=400)

    folder_id = r[0]

    # 🔥 subir archivo nuevo
    created = upload_file(folder_id, archivo, archivo.name)
    file_id = created.get("id")
    file_url = f"https://drive.google.com/file/d/{file_id}/view"

    # 🧹 borrar archivo anterior
    if old_drive_id:
        try:
            delete_file(old_drive_id)
        except:
            pass

    # 🔄 actualizar BD
    with connection.cursor() as cur:
        cur.execute("""
            UPDATE entregas
            SET file_url=%s,
                drive_file_id=%s,
                estado='EN_REVISION',
                updated_at=NOW()
            WHERE id=%s
        """, [file_url, file_id, entrega_id])

    return JsonResponse({
        "success": True,
        "file_url": file_url
    })

def coord_reportes_data():
    with connection.cursor() as cur:
        cur.execute("""
            WITH requeridas AS (
                SELECT 
                    curso_id,
                    tipo_id
                FROM vw_entregas_requeridas_efectivas
            ),
            entregadas AS (
                SELECT DISTINCT
                    curso_id,
                    tipo_id,
                    docente_id
                FROM entregas
            ),
            base AS (
                SELECT 
                    a.docente_id,
                    COUNT(DISTINCT r.curso_id || '-' || r.tipo_id) AS requeridas,
                    COUNT(DISTINCT e.curso_id || '-' || e.tipo_id) AS entregadas
                FROM asignaciones a
                LEFT JOIN requeridas r 
                    ON r.curso_id = a.curso_id
                LEFT JOIN entregadas e 
                    ON e.curso_id = r.curso_id 
                    AND e.tipo_id = r.tipo_id
                    AND e.docente_id = a.docente_id
                GROUP BY a.docente_id
            )
            SELECT 
                d.id,
                d.nombre,
                COALESCE(b.entregadas,0) AS entregadas,
                COALESCE(b.requeridas,0) AS requeridas
            FROM base b
            JOIN docentes d ON d.id = b.docente_id
            ORDER BY 
                (COALESCE(b.entregadas,0) * 1.0 / NULLIF(b.requeridas,0)) DESC NULLS LAST
        """)

        columnas = [col[0] for col in cur.description]
        data = [dict(zip(columnas, fila)) for fila in cur.fetchall()]

    # 🔥 cálculo en Python (seguro)
    for d in data:
        req = d["requeridas"] or 0
        ent = d["entregadas"] or 0

        if req > 0:
            porcentaje = round((ent * 100) / req, 2)
        else:
            porcentaje = 0

        d["porcentaje"] = porcentaje

        if porcentaje >= 80:
            d["semaforo"] = "VERDE"
        elif porcentaje >= 50:
            d["semaforo"] = "AMARILLO"
        else:
            d["semaforo"] = "ROJO"

    return data

def coord_revision_data():
    with connection.cursor() as cur:
        cur.execute("""
            SELECT 
                e.id,
                d.nombre AS docente,
                c.nombre AS curso,
                t.nombre AS tipo,
                e.estado,
                e.file_url
            FROM entregas e
            JOIN docentes d ON d.id = e.docente_id
            JOIN cursos c ON c.id = e.curso_id
            JOIN tipos_entregable t ON t.id = e.tipo_id
            ORDER BY e.created_at DESC
        """)

        columnas = [col[0] for col in cur.description]
        data = [dict(zip(columnas, fila)) for fila in cur.fetchall()]

    return data
    
@require_POST
def cambiar_estado_entrega(request):
    if not _require_coordinator(request):
        return HttpResponseForbidden("No autorizado")

    entrega_id = request.POST.get("entrega_id")
    estado = request.POST.get("estado")

    if estado not in ["EN_REVISION", "REVISADO", "APROBADO"]:
        return JsonResponse({"error": "Estado inválido"}, status=400)

    with connection.cursor() as cur:
        cur.execute("""
            UPDATE entregas
            SET estado = %s,
                updated_at = NOW()
            WHERE id = %s
        """, [estado, entrega_id])

    return JsonResponse({"success": True})

def coord_docente_detalle(request, docente_id):

    with connection.cursor() as cur:

        # 🔵 info docente
        cur.execute("""
            SELECT nombre
            FROM docentes
            WHERE id = %s
        """, [docente_id])
        docente = cur.fetchone()[0]

        # 🟢 resumen
        cur.execute("""
            SELECT 
                COUNT(DISTINCT r.curso_id || '-' || r.tipo_id) AS requeridas,
                COUNT(DISTINCT e.curso_id || '-' || e.tipo_id) AS entregadas
            FROM asignaciones a
            LEFT JOIN vw_entregas_requeridas_efectivas r 
                ON r.curso_id = a.curso_id
            LEFT JOIN entregas e 
                ON e.curso_id = r.curso_id
                AND e.tipo_id = r.tipo_id
                AND e.docente_id = a.docente_id
            WHERE a.docente_id = %s
        """, [docente_id])

        req, ent = cur.fetchone()

        porcentaje = round((ent * 100) / req, 2) if req else 0
        pendientes = req - ent if req and ent else req or 0

        # 🔵 por curso
        cur.execute("""
            SELECT 
                c.nombre,
                COUNT(DISTINCT r.tipo_id) AS requeridas,
                COUNT(DISTINCT e.tipo_id) AS entregadas
            FROM asignaciones a
            JOIN cursos c ON c.id = a.curso_id
            LEFT JOIN vw_entregas_requeridas_efectivas r 
                ON r.curso_id = c.id
            LEFT JOIN entregas e 
                ON e.curso_id = c.id 
                AND e.tipo_id = r.tipo_id
                AND e.docente_id = a.docente_id
            WHERE a.docente_id = %s
            GROUP BY c.nombre
        """, [docente_id])

        cursos_raw = cur.fetchall()

        cursos = []
        for row in cursos_raw:
            nombre = row[0]
            requeridas = row[1]
            entregadas = row[2]

            if requeridas > 0:
                porcentaje = round((entregadas * 100) / requeridas, 2)
            else:
                porcentaje = 0

            cursos.append((nombre, requeridas, entregadas, porcentaje))

        # 🔴 pendientes
        cur.execute("""
            SELECT 
                c.nombre,
                t.nombre
            FROM asignaciones a
            JOIN cursos c ON c.id = a.curso_id
            JOIN vw_entregas_requeridas_efectivas r ON r.curso_id = c.id
            JOIN tipos_entregable t ON t.id = r.tipo_id
            LEFT JOIN entregas e 
                ON e.curso_id = c.id 
                AND e.tipo_id = t.id
                AND e.docente_id = a.docente_id
            WHERE a.docente_id = %s
              AND e.id IS NULL
        """, [docente_id])

        pendientes_lista = cur.fetchall()
        pendientes_total = len(pendientes_lista)

    ###################################
        cur.execute("""
        SELECT 
            t.nombre,
            CASE 
                WHEN COUNT(e.id) > 0 THEN 'ENTREGADO'
                ELSE 'PENDIENTE'
            END as estado
        FROM asignaciones a
        JOIN vw_entregas_requeridas_efectivas r 
            ON r.curso_id = a.curso_id
        JOIN tipos_entregable t 
            ON t.id = r.tipo_id
        LEFT JOIN entregas e 
            ON e.curso_id = r.curso_id 
            AND e.tipo_id = r.tipo_id
            AND e.docente_id = a.docente_id
        WHERE a.docente_id = %s
        GROUP BY t.nombre
        ORDER BY t.nombre
    """, [docente_id])

        tipos = cur.fetchall()

    ###################################

    return render(request, "coord_docente.html", {
        "docente": docente,
        "requeridas": req,
        "entregadas": ent,
        "porcentaje": porcentaje,
        "pendientes_total": pendientes_total,
        "cursos": cursos,
        "pendientes": pendientes_lista,
        "tipos": tipos
    })