# core/models.py
from django.db import models

class Docente(models.Model):
    id = models.IntegerField(primary_key=True)
    documento_id = models.TextField(null=True)
    nombre = models.TextField()
    email = models.TextField(unique=True)
    activo = models.BooleanField()
    class Meta:
        managed = False
        db_table = "docentes"

class Curso(models.Model):
    id = models.IntegerField(primary_key=True)
    semestre = models.TextField()
    nivel = models.IntegerField()
    codigo = models.TextField()
    nombre = models.TextField()
    grupo = models.TextField()
    folder_drive_id = models.TextField()
    class Meta:
        managed = False
        db_table = "cursos"

class TipoEntregable(models.Model):
    id = models.IntegerField(primary_key=True)
    codigo = models.TextField(unique=True)
    nombre = models.TextField()
    unico_por_curso = models.BooleanField()
    solo_piar = models.BooleanField()
    class Meta:
        managed = False
        db_table = "tipos_entregable"

class Entrega(models.Model):
    id = models.IntegerField(primary_key=True)
    curso_id = models.IntegerField()
    docente_id = models.IntegerField()
    tipo_id = models.IntegerField()
    comentario = models.TextField(null=True)
    file_url = models.TextField()
    estado = models.TextField()  # enum en DB, manejamos como texto aquí
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
    class Meta:
        managed = False
        db_table = "entregas"

class Asignacion(models.Model):
    id = models.IntegerField(primary_key=True)
    docente_id = models.IntegerField()
    curso_id = models.IntegerField()
    class Meta:
        managed = False
        db_table = "asignaciones"

# Vistas
class VwPendientes(models.Model):
    # Clave técnica para Django (la proveeremos en el SELECT del .raw)
    id = models.BigIntegerField(primary_key=True)

    # Campos reales de la vista (sin primary_key)
    docente_id = models.IntegerField()
    documento_id = models.TextField(null=True)
    docente_nombre = models.TextField()
    docente_email = models.TextField()
    curso_id = models.IntegerField()
    semestre = models.TextField()
    nivel = models.IntegerField()
    codigo = models.TextField()
    curso_nombre = models.TextField()
    grupo = models.TextField()
    tipo_id = models.IntegerField()
    tipo_codigo = models.TextField()
    tipo_nombre = models.TextField()
    fecha_limite = models.DateField()
    estado_actual = models.TextField()

    class Meta:
        managed = False
        db_table = "vw_pendientes"
