from django.conf import settings
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken

from choices import NATIONALITY_CHOICES, LEGAL_STATUS_CHOICES
from django.dispatch import receiver

from django.db.models.signals import post_save
from django.contrib.auth.models import User

class UserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, phone_number,password=None):
       
       user = self.model(
           email = self.normalize_email(email),
           first_name = first_name.title(),
           last_name = last_name.title(),
           phone_number = phone_number.title(),
           
       )

       user.set_password(password)
       user.save(using=self.db)
       return user 

    
    def create_superuser(self, email, first_name, last_name, phone_number, password=None):   
        user = self.model(
            email = self.normalize_email(email),
            first_name = first_name.title(),
            last_name = last_name.title(),
            phone_number = phone_number.title(),
            
        )

        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.set_password(password)
        user.save(using=self.db)
        return user 


    def create_adminuser(self, email, first_name, last_name, phone_number, password=None):

        user = self.model(
            email = self.normalize_email(email),
            first_name = first_name.title(),
            last_name = last_name.title(),
            phone_number = phone_number.title(),
            

        )
        user.set_password(password)
        user.save(using=self.db)
        return user 

        
AUTH_PROVIDERS = { 'email': 'email' }

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(verbose_name="email", max_length=60, unique=True)
    phone_number = models.CharField(max_length=100, null=False, blank=False, unique=True, default="0770000000")
    first_name = models.CharField(max_length=200, null=True, blank=False)
    last_name = models.CharField(max_length=200,  null=True, blank=False)
  
    otp = models.CharField(max_length=6, null=True, blank=True)
    date_joined = models.DateTimeField(verbose_name='date joined', auto_now_add=True)
    last_login = models.DateTimeField(verbose_name='last login', auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    auth_provider = models.CharField( max_length=255, blank=False, null=False, default=AUTH_PROVIDERS.get('email'))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'phone_number']

    objects = UserManager()

    def __str__(self):
        return "{} {}".format(self.first_name, self.last_name)

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    def tokens(self):
       
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }


class UserProfile(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE )
    image = models.ImageField(default="images/default.jpg")

@receiver(post_save, sender=User)
def save(sender, instance,created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        instance.userprofile.save()
    
