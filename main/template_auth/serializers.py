from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _


class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField()

    def validate(self, data):
        user_model = get_user_model()

        try:
            user = user_model.objects.filter(username=data.get('username'))
            if len(user) > 0:
                raise serializers.ValidationError(_("Username already exists"))
        except user_model.DoesNotExist:
            pass

        if not data.get('password') or not data.get('confirm_password'):
            raise serializers.ValidationError(_("Empty Password"))

        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError(_("Mismatch"))

        return data

    class Meta:
        model = get_user_model()
        fields = ('username', 'first_name', 'last_name', 'password', 'confirm_password', 'is_active')
        extra_kwargs = {'confirm_password': {'read_only': True}}