# Generated by Django 4.2.7 on 2023-12-11 04:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_alter_actor_image_alter_customuser_profile_pic_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='actor',
            name='image',
            field=models.ImageField(default='media/user.jpg', upload_to='media/actors/'),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='profile_pic',
            field=models.ImageField(default='media/user.jpg', null=True, upload_to='media/profile_pics'),
        ),
        migrations.AlterField(
            model_name='director',
            name='image',
            field=models.ImageField(default='media/user.jpg', upload_to='media/directors/'),
        ),
        migrations.AlterField(
            model_name='movie',
            name='posterImage',
            field=models.ImageField(default='media/user.jpg', upload_to='media/posters/'),
        ),
    ]
