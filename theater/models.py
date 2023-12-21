from django.db import models

# Create your models here.
class Theater(models.Model):
    name = models.CharField(max_length=100)
    address = models.TextField()
    totalRoom = models.IntegerField()
    rowCount = models.IntegerField()
    columnCount = models.IntegerField()
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)
    
    def save(self, *args, **kwargs):
        if not self.pk:
            super().save(*args, **kwargs)

            if self.totalRoom:
                # Delete existing rooms
                Room.objects.filter(theater=self).delete()

                # Create new rooms
                for room_number in range(1, self.totalRoom + 1):
                    room = Room.objects.create(
                        theater=self,
                        roomNumber=str(room_number),
                        is_active=True
                    )

                    # Create new seats for the room
                    self.create_seats(room)

    def create_seats(self, room):
        if self.rowCount and self.columnCount:
            # Create new seats
            for row_number in range(1, self.rowCount + 1):
                for column_number in range(1, self.columnCount + 1):
                    seat_number =  f'{chr(ord("A") + row_number - 1)}-{column_number}'
                    
                    # Adjusted price to stay within the valid range
                    price = 9999.99 if row_number not in (self.rowCount - 1, self.rowCount) else 15000

                    Seat.objects.create(
                        room=room,
                        seatNo=seat_number,
                        price=price,
                        is_available=False
                    )

    def __str__(self):
        return self.name

class Room(models.Model):
    theater = models.ForeignKey('Theater', on_delete=models.CASCADE, related_name='rooms', null=True)
    roomNumber = models.CharField(max_length=25)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['roomNumber']
        
    def __str__(self):
        return f'Room {self.roomNumber}'
        
        
class Seat(models.Model):
    room = models.ForeignKey('Room', on_delete=models.CASCADE, related_name='seats', null=True)
    seatNo = models.CharField(max_length=10)
    price = models.DecimalField(decimal_places=2, max_digits=7)
    is_available = models.BooleanField(default=False)

    class Meta:
         ordering = ['room__roomNumber', 'seatNo']
        
    def __str__(self):
        return f'{self.seatNo} in {self.room}'

class PopconsAndDrinks(models.Model):
    types = [
        ('POPCON','Popcon'),
        ('DRINKS','Drink'),
        ('COMBO','Combo'),
    ]
    # seat = models.OneToOneField('Seat', on_delete=models.CASCADE, primary_key=True,
    #                             related_name='popconanddrink')
    name = models.CharField(max_length=100)
    description = models.TextField()
    type = models.CharField(choices=types, max_length=10)
    price = models.DecimalField(decimal_places=2, max_digits=6)
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        def __str__(self):
            return f"Popcons and Drinks for {self.seat}"
        
class Voucher(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10, unique=True)
    startDate = models.DateTimeField()
    endDate = models.DateTimeField()
    discountPercentage = models.FloatField()
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        def __str__(self):
            return f"Voucher with Code {self.code}"
