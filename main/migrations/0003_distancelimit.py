# Generated by Django 3.0.3 on 2020-06-25 22:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0002_forbiddenip'),
    ]

    operations = [
        migrations.CreateModel(
            name='DistanceLimit',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('distanceLimit', models.IntegerField(blank=True, default=10, null=True)),
            ],
        ),
    ]
