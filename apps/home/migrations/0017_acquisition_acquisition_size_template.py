# Generated by Django 5.0.3 on 2024-03-19 12:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0016_acquisition_acquisition_client_ip_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='acquisition',
            name='acquisition_size_template',
            field=models.BigIntegerField(blank=True, default=0, null=True),
        ),
    ]
