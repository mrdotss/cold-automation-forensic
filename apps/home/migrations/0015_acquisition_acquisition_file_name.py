# Generated by Django 5.0.3 on 2024-03-18 09:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0014_acquisition_acquisition_device_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='acquisition',
            name='acquisition_file_name',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
