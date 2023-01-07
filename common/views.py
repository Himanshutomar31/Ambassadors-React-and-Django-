from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import exceptions
from common.serializers import UserSerializer
from core.models import User
from common.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated


# Create your views here.


class RegisterAPIView(APIView):
    def post(self, request):
        data = request.data

        if data['password'] != data['password_confirm']:
            raise exceptions.APIException("Passwords don't match")

        data['is_ambassdor'] = 0
        serializer = UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()
        if user is None:
            raise exceptions.AuthenticationFailed("User not found")

        if not user.check_password(password):
            raise exceptions.AuthenticationFailed('Incorrect Password!')

        token = JWTAuthentication.generate_jwt(user.id)
        response = Response()
        response.set_cookie(key="jwt", value=token, httponly=True)
        response.data = {
            "message": "Success"
        }
        return response


class UserAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        data = UserSerializer(user).data

        if 'api/ambassador' in request.path:
            data['revenue'] = user.revenue

        return Response(data)


class LogoutAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, _):
        response = Response()
        response.delete_cookie(key='jwt')
        response.data = {
            'message': 'success'
        }
        return response


class ProfileInfoAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, pk=None):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ProfilePasswordAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, pk=None):
        user = request.user
        data = request.data

        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Passwords do not match!')

        user.set_password(data['password'])
        user.save()
        return Response(UserSerializer(user).data)
