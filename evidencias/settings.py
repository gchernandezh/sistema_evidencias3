import os
import dj_database_url
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.environ.get("DJ_SECRET", "dev-secret")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DEBUG","0") == "1"

ALLOWED_HOSTS = ["sistema-evidencias2.onrender.com", "127.0.0.1", "localhost", "sistema-evidencias3.onrender.com"]


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin","django.contrib.auth","django.contrib.contenttypes",
    "django.contrib.sessions","django.contrib.messages","django.contrib.staticfiles",
    "corsheaders","rest_framework","core","social_django",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",   # <- justo después de SecurityMiddleware
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = 'evidencias.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'evidencias.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    "default": dj_database_url.config(
        default=os.environ.get("DATABASE_URL"),
        conn_max_age=0,   # 👈 IMPORTANTE
        ssl_require=True,
    )
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = []


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/
LANGUAGE_CODE = "es-co"
TIME_ZONE = "America/Bogota"
USE_TZ = True

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "no-reply@sistema-evidencias.local"
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
# --- Archivos de usuario (subidas) para Fase 1 ---
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
# Subidas (dev)
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 20))  # 20 MB
ALLOWED_UPLOAD_EXTS = os.environ.get(
    "ALLOWED_UPLOAD_EXTS",
    "pdf,doc,docx,xls,xlsx,ppt,pptx"
).split(",")

# Sesión
SESSION_COOKIE_AGE = 60 * 60 * 8   # 8 horas
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "None"
ALLOWED_EMAIL_DOMAIN = os.environ.get("ALLOWED_EMAIL_DOMAIN", "cecar.edu.co")
# Correos que pueden entrar al panel de Coordinación (coma-separados)
COORDINATOR_EMAILS = [e.strip().lower() for e in os.environ.get(
    "COORDINATOR_EMAILS",
    "coordareaingenieriasistemas@cecar.edu.co"
).split(",")]
SESSION_ENGINE = "django.contrib.sessions.backends.db"
# === Google Drive ===
USE_DRIVE = True
# === Google Drive (OAuth de usuario) ===
GOOGLE_OAUTH_CLIENT_SECRETS_FILE = Path(
    os.environ.get("GOOGLE_OAUTH_CLIENT_SECRETS_FILE", "/tmp/client_secret.json")
)
DRIVE_SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
GOOGLE_OAUTH_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "")
GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "")
# === Auth redirects ===
LOGIN_URL = "/login"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login"

# === Social Auth (Google) ===
AUTHENTICATION_BACKENDS = (
    "social_core.backends.google.GoogleOAuth2",
    "django.contrib.auth.backends.ModelBackend",
)

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "")
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "")

# Sugerencia visual para cuentas del dominio (no sustituye la validación de pipeline)
SOCIAL_AUTH_GOOGLE_OAUTH2_AUTH_EXTRA_ARGUMENTS = {
    "hd": os.environ.get("ALLOWED_EMAIL_DOMAIN", "cecar.edu.co")
}

SOCIAL_AUTH_PIPELINE = (
    "social_core.pipeline.social_auth.social_details",
    "social_core.pipeline.social_auth.social_uid",
    "social_core.pipeline.social_auth.auth_allowed",
    "core.pipeline.enforce_institution_domain",   # valida @tu-dominio
    "social_core.pipeline.social_auth.social_user",
    "social_core.pipeline.user.get_username",
    "social_core.pipeline.user.create_user",
    "social_core.pipeline.social_auth.associate_user",
    "social_core.pipeline.social_auth.load_extra_data",
    "social_core.pipeline.user.user_details",
)
SOCIAL_AUTH_RAISE_EXCEPTIONS = False   # evita el traceback
LOGIN_ERROR_URL = "/login"
SOCIAL_AUTH_LOGIN_ERROR_URL = "/login" # a dónde redirigir el error

CSRF_TRUSTED_ORIGINS = [
    "https://sistema-evidencias2.onrender.com",
    "https://*.onrender.com",
]
MIDDLEWARE.insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
# Social Auth detrás de proxy HTTPS (Render)
SOCIAL_AUTH_REDIRECT_IS_HTTPS = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "root": {
        "handlers": ["console"],
        "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO"),
    },
}
# Django 5+: usa STORAGES para staticfiles
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
    # tu storage por defecto para media (si lo usas localmente)
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"location": str(MEDIA_ROOT)},
    },
}
