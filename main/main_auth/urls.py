from django.urls import path, include
from . import views

app_name = 'main_auth'
urlpatterns = [

    path('register/', views.UserRegister.as_view(), name='register_user'),
    path('register_app/', views.register_app_user, name='register_app_user'),

    path('user_activation/<str:token>/', views.user_activation, name='user_activation'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('password_recovery/', views.PasswordRecovery.as_view(), name='password_recovery'),
    path('password_recovery/<str:token>', views.PasswordRecovery.as_view(), name='update_password'),

    path('social_login/<str:backend>/', views.social_register_or_login, name='social_login'),

    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),  # Oauth endpoints
]