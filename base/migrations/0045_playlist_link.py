# Generated by Django 4.1.7 on 2023-04-04 06:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0044_alter_playlist_image_alter_playlist_title'),
    ]

    operations = [
        migrations.AddField(
            model_name='playlist',
            name='link',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
