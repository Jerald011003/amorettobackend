# Generated by Django 4.1.7 on 2023-04-20 05:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0076_heartlist_postofuser'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='heartlist',
            name='profileofuser',
        ),
        migrations.AlterField(
            model_name='heartlist',
            name='postofuser',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
