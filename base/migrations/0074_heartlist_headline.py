# Generated by Django 4.1.7 on 2023-04-20 03:37

import django.contrib.auth.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0073_heartlist'),
    ]

    operations = [
        migrations.AddField(
            model_name='heartlist',
            name='headline',
            field=models.CharField(blank=True, max_length=200, null=True, verbose_name=django.contrib.auth.models.User),
        ),
    ]
