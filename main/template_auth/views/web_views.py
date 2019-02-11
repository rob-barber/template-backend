from django.conf import settings
from django.urls import reverse_lazy
from django.http import HttpResponse
from django.contrib.auth.views import LoginView, LogoutView, PasswordResetConfirmView, FormView
from django.views.generic import TemplateView

from rest_framework import status

from template_auth.services import OauthPasswordResetTokenGenerator
from template_auth.forms import ForgotPasswordForm


class Login(LoginView):
    template_name = 'template_auth/login.html'
    extra_context = {'footer': True}


class Logout(LogoutView):
    pass


class ForgotPassword(FormView):
    template_name = 'template_auth/account_recovery/forgot_password.html'
    form_class = ForgotPasswordForm
    success_url = ''  # we are handling the post request manually so this is not needed

    def post(self, request, *args, **kwargs):
        """
        Handles the forgot password form data sent from the frontend with the POST method. This is a dynamic call
        and will not render a new view. Javascript on the front end will handle prompting the user after receiving
        an Ajax response from this function.

        :param request: The request object.
        :param args: Any arguments sent to the request.
        :param kwargs: Keyword arguments.
        :return: A context object to use for rendering the view.
        """

        form = ForgotPasswordForm(request.POST)

        if form.is_valid():
            from_email = settings.NO_REPLY_EMAIL
            form.send_mail(from_email)

        else:
            return HttpResponse('Malformed Request', status=status.HTTP_400_BAD_REQUEST)

        # We are silently failing internal errors to the user for security
        return HttpResponse('Email Sent', status=status.HTTP_200_OK)


class ResetPassword(PasswordResetConfirmView):
    """
    The screen that allows users to reset their password. This includes both admin users
    as well as mobile users.
    """
    template_name = 'template_auth/account_recovery/password_reset.html'
    token_generator = OauthPasswordResetTokenGenerator()
    success_url = reverse_lazy('template_auth:password_reset_success')


class ResetPasswordSuccess(TemplateView):
    """ Screen that is shown after a user has successfully reset their password """
    template_name = 'template_auth/account_recovery/password_reset_success.html'
