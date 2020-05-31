from django.shortcuts import render
from django.contrib.auth import logout as userlogout
from django.contrib.auth.decorators import login_required

# Create your views here.
from django.http import HttpResponse

def home(request):
    return render(request, "main/home.html", {})

def logout(request):
    userlogout(request)
    return render(request, "main/home.html", {})