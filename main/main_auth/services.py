from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.core.validators import EmailValidator
from django.contrib.auth.password_validation import validate_password

from smtplib import SMTPException

from oauthlib.common import generate_token
from oauth2_provider.models import Application, AccessToken

def validate_create_user_request(request):
    """
    This validates all the data coming into the "create_user" view data. It collects a list of errors and
    returns them to the caller along with a few variables for convenience.

    This expects the following inside the request.data list
    request.data['email']
    request.data['password']

    :param request: The Django Rest Framework request object sent from the client.
    :return: tuple, (validationSuccessful, errorArray). errorArray will only be populated if validationSuccessful is False
    """
    email = request.data['email'] if ('email' in request.data) else None
    password = request.data['password'] if ('password' in request.data) else None

    errors = []  # populate with a list of error messages

    if not (email and password):
        errors.append('Required data not set')

    # Validate email and password
    try:
        EmailValidator().__call__(email)
        validate_password(password)
    except ValidationError as e:
        errors.extend(e.messages)
    except TypeError:
        # password has not been sent to the validate_password will throw a TypeError
        pass


    return (True, errors) if len(errors) == 0 else (False, errors)


def send_activation_email(user):
    """
    Sends an activation email to the user with a link that will direct them to the activation web page

    :param user: The user object containing the email address to send the email to.
    :return: True if successful, False otherwise.
    """

    if user.email is None:
        return False

    # TODO: Set to correct app name when Oauth Toolkit is set up
    oauth_app = Application.objects.get(name=settings.APP_NAME)

    oauth_token = generate_token()


    AccessToken.objects.create(
        user=user,
        application=oauth_app,
        expires=timezone.now() + timezone.timedelta(seconds= settings.RESET_PASSWORD_TOKEN_EXPIRE_SECONDS),
        token=oauth_token
    )

    # Use a reverse url lookup to set the link (this allows us to not worry about hard coding the url if it changes)
    link = settings.SERVER_BASE_URL + \
           reverse(
               'main_app:user_activation',
               kwargs={'token': oauth_token},
               current_app=settings.APP_NAME)

    try:
        send_mail(
            from_email=settings.NO_REPLY_EMAIL,
            subject=settings.ACTIVATION_EMAIL_SUBJECT,
            recipient_list=[user.username],
            message='',
            html_message='<p>' + settings.ACTIVATION_EMAIL_MESSAGE + '</p><br/><br/>'
                         '<a href="' + link + '">' + link + '</a>',
            fail_silently=False,
        )
    except SMTPException:
        return False

    return True


def send_password_recovery_email(user):
    """
    Sends a password recovery email based upon the user parameter

    :param user: The user to send the recovery email for
    :return:
    """
    if user.email is None:
        return -1

    # TODO: Set to correct app name when Oauth Toolkit is set up
    oauth_app = Application.objects.get(name='mogabi')

    oauth_token = generate_token()

    AccessToken.objects.create(
        user=user,
        application=oauth_app,
        expires=timezone.now() + timezone.timedelta(days=1),
        token=oauth_token
    )

    # Use a reverse url lookup to set the link (this allows us to not worry about hard coding the url if it changes)
    link = settings.SERVER_BASE_URL + \
           reverse(
               'main_app:get_password_recovery',
               kwargs={'token': oauth_token},
               current_app='main_app')

    try:
        send_mail(
            from_email= settings.NO_REPLY_EMAIL,
            subject='Test Company' + ' ' + 'Password Recovery',
            recipient_list=[user.username],
            message='Why do I need this????',
            html_message='<p>Please click the link below to navigate to the password recovery page.</p><br/><br/>'
                         '<a href="' + link + '">' + link + '</a>',
            fail_silently=False,
        )
    except SMTPException:
        return -1

    return 1


def validate_oauth_token(token):
    """
    Validates the token and returns the correct user if the token is valid.

    :param token: The oauth token to validate
    :return: The user object if the token is valid, None otherwise
    """
    is_error = False

    if token is None:
        is_error = True

    app = Application.objects.get(name=settings.APP_NAME)

    try:
        activation_token = AccessToken.objects.get(token=token, application=app)
    except AccessToken.DoesNotExist:
        is_error = True  # just being explicit here
        return None, is_error  # we cannot really go any further without the token

    now = timezone.now()

    if activation_token.expires < now:
        return None

    user = activation_token.user

    return user
