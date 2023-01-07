import jwt
import datetime
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from app import settings
from core.models import User


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):

        token = request.COOKIES.get('jwt')

        if not token:
            return None

        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('unauthenticated')

        user = User.objects.get(pk=payload['user_id'])

        if user is None:
            raise exceptions.AuthenticationFailed('User not found!')

        return (user, None)

    @staticmethod
    def generate_jwt(id):
        payload = {
            'user_id': id,
            'expire': str(datetime.datetime.utcnow() + datetime.timedelta(days=1)),
            'iat': int(datetime.datetime.utcnow().strftime('%Y%m%d'))
        }
        token = jwt.encode(payload, settings.SECRET_KEY)
        return token
