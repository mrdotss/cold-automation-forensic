# Generated by Django 5.0.3 on 2024-05-22 10:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0019_alter_acquisition_acquisition_size_template'),
    ]

    operations = [
        migrations.AddField(
            model_name='acquisition',
            name='acquisition_is_verify_first',
            field=models.BooleanField(blank=True, null=True),
        ),
    ]
