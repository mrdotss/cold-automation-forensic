# Generated by Django 5.1.2 on 2024-11-05 08:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0035_alter_acquisition_acquisition_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='selectivefullfilesystemacquisition',
            name='hash_result',
            field=models.TextField(blank=True, null=True),
        ),
    ]