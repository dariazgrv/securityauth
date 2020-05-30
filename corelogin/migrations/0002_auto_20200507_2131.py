# Generated by Django 3.0.3 on 2020-05-07 18:31

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('corelogin', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='logininfo',
            name='phonenumber',
            field=models.CharField(blank=True, default=None, max_length=17, null=True, validators=[django.core.validators.RegexValidator(message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.", regex='^\\+?1?\\d{9,15}$')]),
        ),
    ]
