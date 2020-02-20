from django.shortcuts import render

# Create your views here.


def corelogin(request):
        return render(request, "corelogin/login.html", {})
