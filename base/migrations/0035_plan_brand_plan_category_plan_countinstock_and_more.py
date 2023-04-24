# Generated by Django 4.1.7 on 2023-04-02 06:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0034_remove_plan_brand_remove_plan_category_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='plan',
            name='brand',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='plan',
            name='category',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='plan',
            name='countInStock',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AddField(
            model_name='plan',
            name='createdAt',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='plan',
            name='download',
            field=models.FileField(blank=True, null=True, upload_to=''),
        ),
        migrations.AddField(
            model_name='plan',
            name='image',
            field=models.ImageField(blank=True, default='/placeholder.png', null=True, upload_to=''),
        ),
        migrations.AddField(
            model_name='plan',
            name='numReviews',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AddField(
            model_name='plan',
            name='numofPreorder',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AddField(
            model_name='plan',
            name='preorderdate',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='plan',
            name='rating',
            field=models.DecimalField(blank=True, decimal_places=2, max_digits=7, null=True),
        ),
        migrations.AddField(
            model_name='plan',
            name='watch',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
