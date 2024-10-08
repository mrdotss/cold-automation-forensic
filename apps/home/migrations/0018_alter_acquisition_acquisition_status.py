# Generated by Django 5.0.3 on 2024-03-23 05:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0017_acquisition_acquisition_size_template'),
    ]

    operations = [
        migrations.AlterField(
            model_name='acquisition',
            name='acquisition_status',
            field=models.CharField(choices=[('pending', 'Pending'), ('progress', 'Progress'), ('completed', 'Completed'), ('paused', 'Paused'), ('error', 'Error')], default='pending', max_length=20),
        ),
    ]
