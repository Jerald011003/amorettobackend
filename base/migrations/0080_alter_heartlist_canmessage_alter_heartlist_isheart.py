# Generated by Django 4.1.7 on 2023-04-20 07:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0079_rename_postofuser_heartlist_description_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='heartlist',
            name='canMessage',
            field=models.BooleanField(default=None, null=True),
        ),
        migrations.AlterField(
            model_name='heartlist',
            name='isHeart',
            field=models.BooleanField(default=None, null=True),
        ),
    ]
