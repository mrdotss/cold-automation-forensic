# Generated by Django 5.1.2 on 2024-10-17 16:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0031_remove_evidence_evidence_file_location_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='case',
            name='notes',
        ),
        migrations.AddField(
            model_name='case',
            name='additional_info',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='default_folder',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
