# Generated by Django 4.1.7 on 2023-03-31 09:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0018_friend_comment_friend_rating'),
    ]

    operations = [
        migrations.AddField(
            model_name='product',
            name='preorderdate',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]