from distutils import errors
from django.db import IntegrityError
from django.http import HttpResponse, JsonResponse, HttpResponsePermanentRedirect, Http404

from django.urls import reverse
from django.conf import settings

from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
import jwt
import os


# rest 
from rest_framework.response import Response
from rest_framework import generics, status, views, permissions, generics, permissions, renderers
from rest_framework_simplejwt.tokens import RefreshToken
from yaml import serialize

# account 
from account.models import *
from account.serializers import (
        RegisterSerializer,
        LoginSerializer,
        LogoutSerializer,
        EmailVerificationSerializer,
        ResetPasswordEmailRequestSerializer,
        SetNewPasswordSerializer,
        OtpSerializer,
        UserSerializer
    )
from account.utils import Util, generate_and_send_otp


# swagger
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


class RegisterViewEager(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = [renderers.JSONRenderer]

    def post(self, request):
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        
        # current_site = get_current_site(request).domain
        # relativeLink = reverse('email-verify')
        reset_link = 'http://localhost:8000/account/user/email/verify'+"?token="+str(token)
        body = 'Hi '+ user.first_name + " " + user.last_name + ', Use the link below to verify your email \n' + reset_link
        data = {
            'email_body': body,
            'to_email': user.email,
            'email_subject': 'Verify your email'
        }

        Util.send_email(data)
        return Response({
            'status': 200,
            'mesage': "account created successfully, please verify your email",
            'data': user_data
        })


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = [renderers.JSONRenderer]
    permission_classes  = [permissions.AllowAny]

    def post(self, request):
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        email = serializer.data['email']
       
        generate_and_send_otp(email)

        registered_user = User.objects.get(email=email )
        registered_user_otp = registered_user.otp
        print(registered_user_otp)

        return Response({
            'status': 200,
            'mesage': "account created successfully, please verify your email",
            'data': serializer.data,
            'otp': registered_user_otp
        })


class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer
    queryset = User.objects.all()
    permission_classes  = [permissions.AllowAny]

    def post(self, request):
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    
    serializer_class = LogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({
                "code": 200,
                "message": "logged out successfully"
            },status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({
                "code": 400,
                "message": "Token is not valid"
            })



class RequestPasswordResetEmail(generics.GenericAPIView):

    serializer_class = ResetPasswordEmailRequestSerializer
    permission_classes  = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={ 'uidb64': uidb64, 'token': token})

            # redirect_url = request.data.get('redirect_url', '')
            redirect_url = "http://localhost:8000/account/password/reset/done/"
            absurl = 'http://'+current_site + relativeLink
            body = 'Hello, \n Use link below to reset your password  \n'+absurl+"?redirect_url="+redirect_url

            data = {
                    'email_body': body,
                    'to_email': user.email,
                    'email_subject': 'Reset your passsword'
            }

            Util.send_email(data)
            
            return Response({
                'code': 200,
                'success': 'We have sent you a link to reset your password'
            })
        else:
            return Response({
                'code': 400,
                'error': 'We dont seem to have your email in our database'
            })


class SetNewPasswordAPIView(generics.GenericAPIView):

    serializer_class = SetNewPasswordSerializer
    permission_classes  = [permissions.AllowAny]

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    
    serializer_class = SetNewPasswordSerializer
    permission_classes  = [permissions.AllowAny]

    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)


class Verify_otp(views.APIView):

    permission_classes  = [permissions.AllowAny]

    def post(self,request):
        
        data = request.data
        serializer = OtpSerializer(data = data)
        if serializer.is_valid():
            email = serializer.data['email']
            otp = serializer.data['otp']
            user = User.objects.filter(email=email)
            
            if not user.exists():
                return Response({
                    "code": 400, 
                    "message": "user does not exist in the database"
                })

            if user[0].otp != otp:
                return Response({
                    "code": 400,
                    "message": "otp is invalid"
                })
            user = user.first()
            user.is_verified = True
            user.save()

            return Response({
                "code": 200, 
                "message": "user verified successfully"
            })

        
        return Response({
            "code": 400, 
            "error": serializer.errors
        })

 
class UserList(views.APIView):

    serializer_class = UserSerializer
    
    def get(self, request):
        user = User.objects.all()
        serializer = self.serializer_class(user, many=True)

        return Response({
            "code": 200,
            "users": serializer.data
        })


class UserDeatail(views.APIView):
    
    serializer_class = UserSerializer
    permission_classes  = [permissions.AllowAny]

    def get_object(self, id, format=None):
        try:
            return User.objects.get(id=id)
        except User.DoesNotExist:
            raise Http404

    def get(self, request, id):
        if request.method == "GET":

            try:
                user = User.objects.get(id=id)
                serializer = self.serializer_class(user)  
                return Response({
                    "code": 200,
                    "report": serializer.data
                }, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({
                    "code":400,
                    "message": "report document does not exist"
                }, status=status.HTTP_400_BAD_REQUEST)


    def put(self, request, id, format=None):
        
        if request.method == "PUT":
            
            user = self.get_object(id)

            serializer = self.serializer_class(user, data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "code": 200,
                    "message": "user updated successfully "
                })
            else:
                return Response({
                    "code": 400,
                    "errors": serializer.errors
                })
        
        return Response({
            "code": 200,
            "message": serializer.data
        })

    def delete(self, request, id, format=None):
        user = self.get_object(id)
        user.delete()
        return Response({
            "code": 200,
            "message": "user successfully deleted"
        })


class GetReportById(generics.GenericAPIView):
    
    serializer_class = UserSerializer
    permission_classes  = [permissions.AllowAny]

    # filter_backends = [DjangoFilterBackend]
    # filterset_fields = ['reportid']
    
    

       
    