from django.contrib.auth import authenticate, login, logout
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.generics import CreateAPIView, ListAPIView, RetrieveUpdateAPIView, RetrieveAPIView, RetrieveUpdateDestroyAPIView, ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView
from django.views.decorators.csrf import csrf_exempt
from django.views import View
from paypalrestsdk import Payment, exceptions
from .models import CustomUser, Movie, Actor, Evulation, Showtimes, Booking
from .serializers import UserSerializer, UserRegistSerializer, ProfileSerializer, MovieSerializer, ActorSerializer, ShowtimeSerializer, EvulationSerializer, BookingSerializer

class register_user(CreateAPIView):
    model = CustomUser
    serializer_class = UserRegistSerializer
    def POST(self, request):
        serializer = UserRegistSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class user_login(APIView):

    def post(self, request):
        username = request.data.get('email')
        password = request.data.get('password')

        user = None
        # if '@' in username:
        #     try:
        #         user = CustomUser.objects.get(email=username)
        #     except ObjectDoesNotExist:
        #         pass
    
        if not user: 
            user = authenticate(username=username, password=password)

        if user :
            if user.is_active:
                login(request, user)
                token, _ = Token.objects.get_or_create(user=user)
                return Response({'user': UserSerializer(user).data, 'token': token.key}, status=status.HTTP_200_OK)
            else:
                Response['msg'] = _("Incorrect username or password")
            # login(request, user)
            # return Response({'token': token.key}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class user_logout(APIView):
    # model = CustomUser
    # serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self, request):
        try:
            # request.auth.delete()
            request.user.auth_token.delete()
            logout(request)
            return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserProfile(RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = CustomUser.objects.all()
    serializer_class = ProfileSerializer
    lookup_field = 'fullname'

    def get_object(self):
        queryset = self.get_queryset()
        filter = {self.lookup_field: self.kwargs[self.lookup_field]}
        
        try:
            obj = queryset.get(**filter)
            self.check_object_permissions(self.request, obj)
            return obj
        except CustomUser.DoesNotExist:
            # Customize the response when the object is not found
            return Response({"detail": "Object not found."}, status=status.HTTP_404_NOT_FOUND)

class Movie(ListAPIView, RetrieveAPIView):
    permission_classes = []
    authentication_classes = []
    queryset = Movie.objects.all()
    serializer_class = MovieSerializer

class Actor(ListAPIView, RetrieveAPIView):
    permission_classes = []
    authentication_classes = []
    queryset = Actor.objects.all()
    serializer_class = ActorSerializer

class Showtime(ListAPIView, RetrieveAPIView):
    permission_classes = []
    authentication_classes = []
    queryset = Showtimes.objects.all()
    serializer_class = ShowtimeSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        # Extract values from URL parameters if available
        showtime = self.kwargs.get('showtime')
        pk = self.kwargs.get('pk')

        # Build the filter based on the presence of parameters
        filter_kwargs = {}
        if showtime is not None:
            filter_kwargs['showtime'] = showtime
        if pk is not None:
            filter_kwargs['pk'] = pk

        # Filter the queryset based on the constructed filter_kwargs
        return queryset.filter(**filter_kwargs)

    def get_object(self):
        queryset = self.get_queryset()
        filter = {"id","showtime"}
        for field in self.multiple_lookup_fields:
            filter[field] = self.kwargs[field]

        try:
            obj = queryset.get(**filter)
            self.check_object_permissions(self.request, obj)
            return obj
        except Showtimes.DoesNotExist:
            # Customize the response when the object is not found
            return Response({"detail": "Object not found."}, status=status.HTTP_404_NOT_FOUND)

class Evulation(ListCreateAPIView, RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = Evulation.objects.all()
    serializer_class = EvulationSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        # Extract values from URL parameters if available
        movie_id = self.kwargs.get('idMovie')
        user_id = self.kwargs.get('idUser')
        pk = self.kwargs.get('pk')

        # Build the filter based on the presence of parameters
        filter_kwargs = {}
        if movie_id is not None:
            filter_kwargs['movie_id'] = movie_id
        if user_id is not None:
            filter_kwargs['user_id'] = user_id
        if pk is not None:
            filter_kwargs['pk'] = pk

        # Filter the queryset based on the constructed filter_kwargs
        return queryset.filter(**filter_kwargs)

    def get_object(self):
        queryset = self.get_queryset()
        filter = {"id","idUser","idMovie"}
        for field in self.multiple_lookup_fields:
            filter[field] = self.kwargs[field]

        try:
            obj = queryset.get(**filter)
            self.check_object_permissions(self.request, obj)
            return obj
        except Showtimes.DoesNotExist:
            # Customize the response when the object is not found
            return Response({"detail": "Object not found."}, status=status.HTTP_404_NOT_FOUND)

class Bookings(ListCreateAPIView, RetrieveAPIView):
    permission_classes = []
    authentication_classes = []
    queryset = Booking.objects.all()
    serializer_class = BookingSerializer

class PayPalPaymentView(View):
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, booking_id):
        booking = get_object_or_404(Booking, id=booking_id)

        # Create a PayPal payment object
        payment = Payment({
            "intent": "sale",
            "payer": {"payment_method": "paypal"},
            "redirect_urls": {
                "return_url": f"{request.build_absolute_uri('/')}/api/paypal/success/",
                "cancel_url": f"{request.build_absolute_uri('/')}/api/paypal/cancel/",
            },
            "transactions": [
                {
                    "amount": {"total": str(booking.totalPrice), "currency": "USD"},
                    "description": f"Booking #{booking.id}",
                }
            ],
        })

        if payment.create():
            # Save the PayPal payment ID to the booking
            booking.paypal_payment_id = payment.id
            booking.save()

            # Get the approval URL from the payment links
            for link in payment.links:
                if link.rel == "approval_url":
                    approval_url = link.href
                    return Response({"redirect_url": approval_url}, content_type="application/json")

        return Response({"detail": "Error creating PayPal payment"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class PayPalSuccessView(View):
    def get(self, request):
        payment_id = request.GET.get('paypal_payment_id')
        booking_id = request.GET.get('id')

        try:
            payment = Payment.find(payment_id)
            booking = Booking.objects.get(id=booking_id)

            if payment.execute({"payer_id": request.GET.get('PayerID')}):
                # Payment executed successfully
                booking.status = 'Successful'
                booking.save()
                return Response({"detail":"Payment executed successfully"}, status=status.HTTP_201_CREATED)
            else:
                return Response({"detail":"Payment execution failed"}, status=status.HTTP_400_BAD_REQUEST)

        except exceptions.PayPalRESTAPIException as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PayPalCancelView(View):
    def get(self, request):
        booking_id = request.GET.get('id')
        booking = Booking.objects.get(id=booking_id)

        # Handle payment cancellation
        booking.status = 'Failed'
        booking.save()

        return Response({"detail":"Payment cancelled"})