# Generated by Django 4.2.7 on 2023-12-28 11:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_remove_booking_seat_booking_seat'),
    ]

    operations = [
        migrations.AlterField(
            model_name='booking',
            name='seat',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]