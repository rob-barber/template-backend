from django.urls import path, include
from .views import mobile_views, web_views

app_name = 'template_auth'
urlpatterns = [

    # Web Based Account register/login
    path('login/', web_views.Login.as_view(), name='login'),
    path('logout/', web_views.Logout.as_view(), name='logout'),
    path('forgot_password/', web_views.ForgotPassword.as_view(), name='forgot_password'),

    # Includes Mobile devices
    path('password_reset/', web_views.ResetPassword.as_view(), name='password_reset'),
    path('password_reset/<uidb64>/<token>/', web_views.ResetPassword.as_view(), name='password_reset'),
    path('reset_success/', web_views.ResetPasswordSuccess.as_view(), name='password_reset_success'),




    # path('register/', views.UserRegister.as_view(), name='register_user'),
    # path('register_app/', views.register_app_user, name='register_app_user'),
    #
    # path('user_activation/<str:token>/', views.user_activation, name='user_activation'),
    # path('forgot_password/', views.forgot_password, name='forgot_password'),
    # path('password_recovery/', views.PasswordRecovery.as_view(), name='password_recovery'),
    # path('password_recovery/<str:token>', views.PasswordRecovery.as_view(), name='update_password'),

    path('social_login/<str:backend>/', mobile_views.social_register_or_login, name='social_login'),

    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),  # Oauth endpoints
]