from django.contrib import admin
from .models import CustomUser, Movie, Showtimes, Evulation, Actor, Booking

# Register your models here.
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'fullname', 'number', 'dateBirth', 'address', 'is_active', 'is_staff']
    list_editable = ['is_active', 'is_staff']
    list_filter = ['email', 'fullname', 'number']

class Showtime(admin.ModelAdmin):
    list_display = ['movie','roomNumber', 'showtime', 'available']
    list_editable= ['available']
    list_filter = ['movie', 'showtime']

class Film(admin.ModelAdmin):
    list_display = ['title', 'release_date', 'genre', 'views', 'rating', 'isAvailable']
    list_editable = ['isAvailable']
    list_filter = ['title', 'release_date', 'genre', 'views', 'rating', 'isAvailable']

class Person(admin.ModelAdmin):
    list_display = [ 'name', 'image',]

class Order(admin.ModelAdmin):
    list_display = ['user','fullname', 'email','number','totalPrice', 'status', 'bookedAt']
    list_editable = ['status']
    list_filter = ['user','fullname', 'email','number', 'status', 'bookedAt']

admin.site.register(CustomUser, UserAdmin)
admin.site.register(Movie, Film)
# admin.site.register(Director, Person)
admin.site.register(Actor, Person)
admin.site.register(Showtimes,Showtime)
admin.site.register(Evulation)
admin.site.register(Booking)