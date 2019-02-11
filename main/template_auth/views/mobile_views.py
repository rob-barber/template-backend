from django import forms
from django.conf import settings
from django.db import transaction
from django.db.utils import IntegrityError
from django.utils import timezone
from django.shortcuts import render
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

from rest_framework import generics
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, authentication_classes, permission_classes

from oauth2_provider.models import Application, AccessToken, RefreshToken
from oauthlib.common import generate_token

from social_django.utils import psa

from braces.views import CsrfExemptMixin

from template_auth.services import send_activation_email, send_password_recovery_email
from template_auth.forms import ForgotPasswordForm

from django.http import HttpResponse


@api_view(['POST'])
@authentication_classes((BasicAuthentication,))
@permission_classes((IsAuthenticated,))
def register_app_user(request):
    """
    Takes certain parameters within the request and creates a new user. This function is catered towards app users since
    they will not have a CSRF token.

    NOTE: This uses basic authentication. A default user needs to be seeded within the database for this to work.

    The following request parameters are required.:
    "email": string,                # This will be the username of the new user
    "password": string,             # The password for the user
    "confirm_password": string      # The confirm password for validation (this should be done on the client but is here as sanity check)

    :param request:
    :return: List of strings containing success or error responses.
             201 created if successful, 400 bad request if data is malformed or if a user already exists
    """

    email = request.data['email'] if ('email' in request.data) else None
    password = request.data['password'] if ('password' in request.data) else None
    confirm_password = request.data['confirm_password'] if ('confirm_password' in request.data) else None

    if email is None or password is None or confirm_password is None:
        return Response('Missing data', status=status.HTTP_400_BAD_REQUEST)

    # Validate Data
    data_validation_errors = []  # Return a list of errors so the user can fix them all at once.

    if password != confirm_password:
        data_validation_errors.append("Password fields don't match")

    try:
        EmailValidator().__call__(email)
        validate_password(password)
    except ValidationError as e:
        data_validation_errors.extend(e.messages)

    if len(data_validation_errors) > 0:
        return Response(data_validation_errors, status=status.HTTP_400_BAD_REQUEST)

    # Try to create the new user. If a user with that username already exists then return an error
    try:
        user_model = get_user_model()

        user = user_model.objects.create_user(
            username=email,
            email=email,
            password=password,
            is_active=False
        )
    except IntegrityError:
        # This user already exists
        return Response(f'User {email} already exists.', status=status.HTTP_409_CONFLICT)

    # finally send out the activation email
    success = send_activation_email(user)

    if not success:
        return Response('Could not send email', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response(f'Success. An activation email has been sent to: {email}', status=status.HTTP_201_CREATED)


@api_view(['POST'])
@authentication_classes((BasicAuthentication,))
@permission_classes((IsAuthenticated,))
def forgot_password(request):
    """
    Sends a password recovery link to the email specified within the body of the request.

    Request parameters:
    email: string The email address

    :param request:
    :return:
    """

    forgot_password_form = ForgotPasswordForm(data=request.data)

    if forgot_password_form.is_valid():
        forgot_password_form.send_mail(settings.NO_REPLY_EMAIL)

    else:
        return Response('Please enter a valid email', status=status.HTTP_400_BAD_REQUEST)

    return Response('Recovery email sent', status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes((BasicAuthentication,))
@permission_classes((IsAuthenticated,))
@psa('social:complete')
def social_register_or_login(request, backend):
    """
    This view uses a social access_token to either register or login a user using a social account (i.e. Facebook,
    Twitter etc...). As of right now Facebook is the only one supported but this can easily be extended to any
    third party social login.

    The access token provided to this view will be used to gather end-user specific information and use that to create
    a new user

    Make a request to this view like this: https://mywebsite.com/social_login/facebook/
    The "facebook/" part tells the view what backend to use for authenticating and creating the user.

    This view expects the following request parameters.
    {
        "access_token":string,   # The access token provided from Facebook, Twitter etc...
    }

    :param request:
    :param backend:
    :return:
    """
    # TODO: Combine social accounts with email accounts. This will need a custom validator for normal email login
    #       since we will be using the social username for the email username. This means we will need to validate
    #       normal email login against the email field in a User and not the username.

    social_token = request.data['access_token'] if ('access_token' in request.data) else None

    if social_token is None:
        return Response('Missing data', status=status.HTTP_400_BAD_REQUEST)

    # Creates a new user in the database from the social account that the token comes from
    user = request.backend.do_auth(social_token)

    if user:

        app = Application.objects.get(name=settings.OAUTH_APP_NAME)

        # Delete the old token if there is one
        try:
            old_token = AccessToken.objects.get(user=user, application=app)
        except AccessToken.DoesNotExist:
            pass
        else:
            old_token.delete()

        # Generate new Oauth tokens for use within this project
        oauth_token = generate_token()
        raw_refresh_token = generate_token()

        access_token_expire_seconds = settings.ACCESS_TOKEN_EXPIRE_SECONDS

        # Create record of Oauth Token so the auth system can use it.
        access_token = AccessToken.objects.create(
            user=user,
            application=app,
            scope='read write groups',
            expires=timezone.now() + timezone.timedelta(seconds=access_token_expire_seconds),
            token=oauth_token
        )

        # Create refresh token so the user won't have to login again unless they logout
        refresh_token = RefreshToken.objects.create(
            user=user,
            token=raw_refresh_token,
            application=app,
            access_token=access_token,
        )

        json_data = {
            "access_token": oauth_token,
            "expires_in": access_token_expire_seconds,
            "token_type": "Bearer",
            "scope": "read write groups",  # TODO: Set correct scope
            "refresh_token": refresh_token.token
        }

        return Response(json_data, status=status.HTTP_201_CREATED)
    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)
