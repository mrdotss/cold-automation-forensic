# Generated by Django 5.0.1 on 2024-02-29 09:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0010_acquisition'),
    ]

    operations = [
        migrations.AddField(
            model_name='acquisition',
            name='acquisition_hash',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='acquisition',
            name='acquisition_last_active',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='acquisition',
            name='acquisition_resume_from_byte',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='acquisition',
            name='acquisition_status',
            field=models.CharField(choices=[('pending', 'Pending'), ('completed', 'Completed'), ('paused', 'Paused'), ('error', 'Error')], default='pending', max_length=20),
        ),
    ]
