# evidencias/urls.py
from django.contrib import admin
from django.urls import path, include
from core import views

# ⬅️ Importamos settings y static
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path("", views.home_switch, name="home"),
    path("dashboard/", views.docente_dashboard, name="docente_dashboard"),
    path("admin/", admin.site.urls),
    path("login", views.login_google_only, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("auth/", include("social_django.urls", namespace="social")),
    # (si ya no usarás “link mágico”, puedes borrar estas dos)
    path("auth/send-link", views.send_magic_link, name="send_link"),
    path("auth/verify", views.verify_magic_link, name="verify_link"),
    path("coord/", views.coord_panel, name="coord_panel"),
    path("coord/toggle-rubrica/", views.coord_toggle_rubrica, name="coord_toggle_rubrica"),
    path("coord/piar/", views.coord_piar, name="coord_piar"),
    path("coord/piar/avance/", views.coord_piar_avance, name="coord_piar_avance"),
    path("coord/toggle-cierre/", views.coord_toggle_cierre, name="coord_toggle_cierre"),
    path("drive/auth", views.drive_auth, name="drive_auth"),
    path("drive/callback", views.drive_callback, name="drive_callback"),
    path("drive/status", views.drive_status, name="drive_status"),
    path("entregar", views.subir_entrega, name="subir_entrega"),
    path("entregar/", views.subir_entrega),  # compatibilidad si alguien pone la barra
    path("docente/correcciones/", views.visualizacion_correcciones, name="visualizacion_correcciones"),
]
# Solo en desarrollo: servir /static/ y /media/
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0])
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
