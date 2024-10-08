# Generated by Django 4.1.3 on 2023-01-23 09:51

import apps.home.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('user_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('user_name', models.CharField(max_length=50)),
                ('user_email', models.CharField(max_length=50, unique=True)),
                ('user_roles', models.CharField(choices=[('Investigator', 'Investigator'), ('Forensics Analyst', 'Forensics Analyst'), ('Lab Technician', 'Lab Technician')], max_length=30)),
                ('user_phone', models.CharField(max_length=15)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_edited_at', models.DateTimeField(auto_now=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_superuser', models.BooleanField(default=False)),
                ('last_login', models.DateTimeField(blank=True, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'User',
                'verbose_name_plural': 'Users',
            },
            managers=[
                ('object', apps.home.models.CustomUserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Case',
            fields=[
                ('case_id', models.UUIDField(default=uuid.UUID('2cd3f5cc-4df1-450d-b076-301693c26200'), editable=False, primary_key=True, serialize=False)),
                ('case_name', models.CharField(max_length=30)),
                ('case_status', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_edited_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Log',
            fields=[
                ('log_id', models.UUIDField(default=uuid.UUID('ed8a1a6b-5fc3-486b-aab4-9a5a1a7fd759'), editable=False, primary_key=True, serialize=False)),
                ('log_action', models.CharField(max_length=10)),
                ('log_data_type', models.CharField(max_length=20)),
                ('log_old_value', models.CharField(max_length=255)),
                ('log_new_value', models.CharField(max_length=255)),
                ('caf_log_created_at', models.DateTimeField(auto_now_add=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='home.case')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Evidence',
            fields=[
                ('evidence_id', models.UUIDField(default=uuid.UUID('8477174b-0b9a-4d6c-938d-14459b96a0ae'), editable=False, primary_key=True, serialize=False)),
                ('evidence_type', models.CharField(max_length=30)),
                ('evidence_file_location', models.ImageField(upload_to=apps.home.models.file_path_document)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_edited_at', models.DateTimeField(auto_now=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='home.case')),
            ],
        ),
    ]
