# Generated by Django 4.1.7 on 2023-04-20 07:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0080_alter_heartlist_canmessage_alter_heartlist_isheart'),
    ]

    operations = [
        migrations.AlterField(
            model_name='heartlist',
            name='canMessage',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='heartlist',
            name='isHeart',
            field=models.BooleanField(default=False),
        ),
    ]
