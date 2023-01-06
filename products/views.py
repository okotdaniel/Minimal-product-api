
from account.models import User
from rest_framework import generics, permissions, status, renderers, exceptions
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.response import Response

from django.http import Http404
from products.serializers import *
from products.models import * 



class ProductListView(generics.GenericAPIView):
        
    serializer_class = ProductSerializer

    def get(self,request, *args, **kwargs):
        
        drink = Product.objects.all()
        serializer = self.serializer_class(drink, many=True)
        return Response({
            "code":status.HTTP_200_OK,
            "data": serializer.data
        }, status = status.HTTP_200_OK)


class ProductCreateView(generics.GenericAPIView):

    serializer_class = ProductSerializer

    def post(self, request):

        if request.method == "POST":
            serializer = self.serializer_class(data= request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "code": 201,
                    "message": " product  addeed succesffully"
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "code": 400,
                    "message": "something wrong happend",
                    "errors": serializer.errors
                }, status= status.HTTP_400_BAD_REQUEST)


class ProductUpdateView(generics.GenericAPIView):

    serializer_class = ProductSerializer

    def get_object(self, id):
        try:
            return Product.objects.get(id=id)
        except Product.DoesNotExist:
            raise Http404

    def put(self, request, id):

        if request.method == "PUT":
            drink = self.get_object(id)
            serializer = self.serializer_class(drink, data=request.data)
       
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "code": 206,
                    "message": "product updated succesffully"
                }, status= status.HTTP_206_PARTIAL_CONTENT)
            else:
                return Response({
                    "code": 400,
                    "message": "something wrong happend"
                }, status = status.HTTP_400_BAD_REQUEST)


class ProductDeleteView(generics.GenericAPIView):
    
    serializer_class = ProductSerializer

    def get_object(self, id):
        try:
            return Product.objects.get(id=id)
        except Product.DoesNotExist:
            raise Http404


    def delete(self, id):
        drink = self.get_object(id)

        drink.delete(id)
        return Response({
            "code":202,
            "message": "product deleted successfully"
        }, status = status.HTTP_202_ACCEPTED)


    
