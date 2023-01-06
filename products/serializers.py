from rest_framework import serializers
from products.models import *
from account.models import User


class ProductSerializer(serializers.ModelSerializer):
   
    class Meta:
        model = Product
        fields = '__all__'
        depth=1


        



        
