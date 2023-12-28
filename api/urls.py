from django.urls import path
# from knox import views as knox_views
from .views import *

urlpatterns = [
    path('register/', register_user.as_view(), name='register'),
    path('login/', user_login.as_view(), name='login'),
    path('logout/', user_logout.as_view(), name='logout'),
    path('users/profile/<str:fullname>/', UserProfile.as_view(), name='profile'),
    
    path('movies/', Movie.as_view(), name='all-movies'),
    path('movies/<str:title>/', Movie.as_view(), name='movies'),

    # path('directors/', Director.as_view(), name='all-directors'),
    # path('directors/<int:pk>/', Director.as_view(), name='directors-detail'),
    path('actors/', Actor.as_view(), name='all-actors'),
    path('actors/<int:pk>/', Actor.as_view(), name='actors'),

    path('showtimes/', Showtime.as_view(), name='all-showtimes'),
    path('showtimes/<int:pk>/', Showtime.as_view(), name='showtimes-id'),
    # path('showtimes/<str:showtime>/', Showtime.as_view(), name='showtimes-by-date'),
    # path('showtimes/<int:pk>/<str:showtime>/', Showtime.as_view(), name='showtimes-by-date-id'),

    path('evulations/<int:idMovie>/', Evulation.as_view(), name='evulation'),
    path('evulations/<int:idMovie>/<int:pk>/', Evulation.as_view(), name='evulation'),

    path('bookings/', Bookings.as_view(), name='booking'),
    path('bookings/<int:pk>/', Bookings.as_view(), name='booking-id'),

    # path('paypal/payment/', PayPalPaymentView.as_view(), name='paypal-payment'),
    # path('paypal/success/', PayPalSuccessView.as_view(), name='paypal-success'),
    # path('paypal/cancel/', PayPalCancelView.as_view(), name='paypal-cancel'),

    path('paypal/create/order', CreateOrderViewRemote.as_view(), name='ordercreate'),
    path('paypal/capture/order', CaptureOrderView.as_view(), name='captureorder'),

    path('dialogflow-webhook/', dialogflow_webhook, name='dialogflow_webhook'),
    
]