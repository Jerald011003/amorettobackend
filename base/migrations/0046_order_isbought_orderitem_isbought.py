# Generated by Django 4.1.7 on 2023-04-06 04:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0045_playlist_link'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='isBought',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='orderitem',
            name='isBought',
            field=models.BooleanField(default=True),
        ),
    ]