# Generated by Django 4.2.7 on 2023-12-28 11:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_showtimes_available_seats_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='booking',
            name='seat',
        ),
        migrations.AddField(
            model_name='booking',
            name='seat',
            field=models.CharField(default=2, max_length=100),
            preserve_default=False,
        ),
    ]