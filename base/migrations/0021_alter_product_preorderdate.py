# Generated by Django 4.1.7 on 2023-03-31 09:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0020_alter_product_preorderdate'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='preorderdate',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]