# Generated by Django 4.1.7 on 2023-03-31 16:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0025_alter_orderitem_download'),
    ]

    operations = [
        migrations.AlterField(
            model_name='order',
            name='download',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]