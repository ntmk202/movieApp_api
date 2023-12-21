from django.contrib import admin
from .models import *

# Register your models here.

admin.site.register(Theater)
admin.site.register(Room)
admin.site.register(Seat)
admin.site.register(PopconsAndDrinks)
admin.site.register(Voucher)