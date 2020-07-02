from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from corelogin.models import LoginInfo

class RegisterForm(UserCreationForm):
    # email = forms.EmailField()

    class Meta:
        model = User
        fields = ["username","password1","password2"]


class ExtraInfo(forms.ModelForm):


    class Meta:

        model = LoginInfo
        fields = ["phonenumber",]