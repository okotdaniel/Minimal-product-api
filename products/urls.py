
from django.urls import path, include
from products.views import *

urlpatterns = [
    path('', ProductListView.as_view(), name="list-product-view"),
    path('create', ProductCreateView.as_view(), name="create-product-view"),
    path('update/<int:id>', ProductUpdateView.as_view(), name="update-product-view"),
    path('delete/<int:id>', ProductDeleteView.as_view(), name="delete-product-view"),

]