from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import CustomUser, Movie, Actor, Evulation, Showtimes, Booking
from theater.models import Room, Seat, PopconsAndDrinks, Voucher


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('email', 'password')
        
class UserRegistSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['fullname', 'email', 'number', 'password', 'dateBirth', 'address', 'profile_pic']
        extra_kwargs = {'password': {'write_only': True}}
        # multiple_lookup_fields = ['fullname']

    def validate_username(self, value):
        # Kiểm tra xem tên người dùng đã tồn tại hay chưa
        if CustomUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("Tên người dùng đã được sử dụng.")
        return value

    def validate_email(self, value):
        # Kiểm tra địa chỉ email đã tồn tại hay chưa
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Địa chỉ email đã được sử dụng.")
        return value

    def create(self, validated_data):
        user = CustomUser(
            fullname=validated_data['fullname'],
            email=validated_data['email'],
            number=validated_data['number'],
            dateBirth=validated_data['dateBirth'],
            address=validated_data['address'],
            profile_pic=validated_data['profile_pic']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id','fullname', 'email', 'number', 'password', 'dateBirth', 'address', 'profile_pic')

class OneTimeUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('fullname', 'email', 'number')

class RoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Room
        fields = ('id', 'roomNumber')

class SeatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Seat
        fields = "__all__"

class VoucherSerializer(serializers.ModelSerializer):
    class Meta:
        model = Voucher
        fields = "__all__"

class SnacksSerializer(serializers.ModelSerializer):
    class Meta:
        model = PopconsAndDrinks
        fields = "__all__"

# class DirectorSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Director
#         # fields = ('id','name', 'image', 'birthday', 'nationality', 'bio')
#         fields = "__all__"

class ActorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Actor
        # fields = ('id','name', 'image', 'birthday', 'nationality', 'bio')
        fields = "__all__"

class MovieSerializer(serializers.ModelSerializer):
    # director = DirectorSerializer(read_only=True)
    actors = ActorSerializer(read_only=True, many=True)
    class Meta:
        model = Movie
        # fields = ('id','title', 'genre', 'trailer', 'director', 'actors', 'durationInMinutes', 'release_date', 'language', 'description', 'posterImage', 'views', 'rating', 'isAvailable')
        fields = "__all__"

class MovieDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Movie
        fields = ('id','title', 'durationInMinutes', 'release_date', 'posterImage',)

class ShowtimeSerializer(serializers.ModelSerializer):
    movie = MovieSerializer(read_only=True)
    roomNumber = RoomSerializer(read_only=True)
    class Meta:
        model = Showtimes
        fields = "__all__"

class EvulationSerializer(serializers.ModelSerializer):
    movie = MovieDetailSerializer(read_only=True)
    user = ProfileSerializer(read_only=True)
    class Meta:
        model = Evulation
        fields = "__all__"

class BookingSerializer(serializers.ModelSerializer):
    user = ProfileSerializer(read_only=True)
    showtime = ShowtimeSerializer(read_only=True)
    voucher = VoucherSerializer(read_only=True)
    snacks = SnacksSerializer(read_only=True)
    class Meta:
        model = Booking
        fields = "__all__"


