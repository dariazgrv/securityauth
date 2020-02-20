from django.urls import path

from . import views

urlpatterns = [
    path("login", views.corelogin, name="login"),

]
