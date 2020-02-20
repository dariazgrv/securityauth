from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse


def index(request):
    return HttpResponse("Home of Main!")

def home(request):
    return render(request, "main/home.html", {})
