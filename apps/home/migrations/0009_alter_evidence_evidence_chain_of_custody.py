# Generated by Django 4.2 on 2023-05-08 18:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0008_remove_evidence_evidence_chain_of_custody_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='evidence',
            name='evidence_chain_of_custody',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
    ]
