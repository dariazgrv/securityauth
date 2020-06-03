from django.shortcuts import render,redirect, HttpResponseRedirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.urls import reverse
from django.contrib.gis.geoip2 import GeoIP2
from django.contrib.auth.models import User
import datetime
from twilio.rest import Client
from django.utils import timezone
from math import cos, asin, sqrt, pi
import random, itertools
from datetime import timedelta
from django.core.signing import TimestampSigner
import base64
from Crypto.Cipher import AES
import shodan

# Create your views here.

#global var

def generate_secure_code():
        choices = [''.join(x) for x in itertools.permutations('0123456789', 5)]
        code = random.choice(choices)

        return code

def get_client_ip(request):
        api = shodan.Shodan('Ppv7mH72xsimqNde3Vq2MgaDyGEtScFm')
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
                print(ip)
                try:

                        ipinfo = api.host(ip)
                        if 'tags' in ipinfo and 'vpn' in ipinfo['tags']:
                                print('{} is connecting from VPN'.format(ip))
                except shodan.APIError as e:
                        print('Error: {}'.format(e))

        else:
                ip = request.META.get('REMOTE_ADDR')
                try:

                        ipinfo = api.host(ip)
                        if 'tags' in ipinfo and 'vpn' in ipinfo['tags']:
                                print('{} is connecting from VPN'.format(ip))
                except shodan.APIError as e:
                        print('Error: {}'.format(e))
                
        return ip

def get_client_city(ip):
        g = GeoIP2()
        # lat,long = g.lat_lon('84.117.7.56')
        # print(lat)
        # print(long)
        city = g.city(ip)
        print(city)

        return city
        

def get_client_last_login(username):
        last_login = User.objects.get(username=username).last_login
        # print('Hour is: ',last_login.hour)
        if last_login is not None:
                return last_login
        else:
                return timezone.now()
        #should add a more elaborate comparison

def calculate_time_between_logins(now,last_login):


        date_time_difference = now - last_login
        date_time_difference_in_minutes = date_time_difference.seconds / 3600
        print(date_time_difference_in_minutes)
        return date_time_difference_in_minutes


def calculate_score_of_trust(ip,username):
        get_client_city(ip)
        user = User.objects.get(username=username)

        risk_score = 0

        now  = timezone.now()
        #now = datetime.datetime.now() #get current time of login attempt
        last_login = get_client_last_login(username)  # get last login time

        previous_city = user.logininfo.city
        current_city = get_client_city(ip)["city"]
        current_lat = get_client_city(ip)["latitude"]
        current_lon = get_client_city(ip)["longitude"]

        previous_lat = user.logininfo.latitude
        previous_lon = user.logininfo.longitude
        time_between_logins = calculate_time_between_logins(now,last_login)
        
        if current_city != previous_city : #daca orasul curent difera de cel anterior
                risk_score = risk_score + 10 #avem deja un risc de +10
                if time_between_logins < 2: #daca timpul intre login-uri este mai mic de 2 ore
                        # inseamnca ca intr-un timp scurt userul a incercat sa se logheze din 2
                        # orase diferite, deci riscul creste cu +10
                        risk_score = risk_score + 10
                        #deci vom calcula distanta, pt a vedea daca e posibil sa ajunga de la o locatia la alta in timpul dat
                        distance = calculate_lat_long_distance(current_lat,current_lon,previous_lat,previous_lon)
                        if distance > 100: #daca distanta e mai mare de 100km
                                risk_score = risk_score + 10 #riscul creste cu +10
                                possible = can_user_travel_there_in_that_amonut_of_time(distance, time_between_logins)
                                #verificam daca era era posibil sa ajunga acolo in timpul dat
                                if possible == False: #iar daca nu era posibil fizic
                                        #trigger_2FA() il obligam sa se logheze prin 2FA
                                        risk_score = risk_score + 10 #pana acum ajunge la maxim 40 ?
                else:
                        distance = calculate_lat_long_distance(current_lat, current_lon, previous_lat, previous_lon)
                        possible = can_user_travel_there_in_that_amonut_of_time(distance,time_between_logins)
                        if possible == False:
                                risk_score = risk_score + 10


        else:
                risk_score = 0

        return risk_score


        # if distance is big and time difference between logins is small, deny access/ redirect to 2FA

def can_user_travel_there_in_that_amonut_of_time(distance,time_between_logins):
        if distance > 1000 and time_between_logins > 24:
                return True
        return False

def calculate_lat_long_distance(lat1,lon1,lat2,lon2):
        #using Haversine formula
        p = pi / 180
        a = 0.5 - cos((lat2 - lat1) * p) / 2 + cos(lat1 * p) * cos(lat2 * p) * (1 - cos((lon2 - lon1) * p)) / 2
        return 12742 * asin(sqrt(a))

def corelogin(request):
        ip = get_client_ip(request)
        #allowed_IPs = ['192.168.10.10','127.0.0.1']
        #print(ip)

        # lat1 = 44.409771
        # lon1 = 26.123591
        # lat2 = 44.452691
        # lon2 = 26.085998
        #
        # print("The distance is: ")
        # print(calculate_lat_long_distance(lat1,lon1,lat2,lon2))

        # get_client_city(ip)
        # get_client_last_login(request)

        if request.method == 'POST':
                form = AuthenticationForm(request=request, data=request.POST)
                if form.is_valid():
                        username = form.cleaned_data.get('username')
                        password = form.cleaned_data.get('password')

                        user = authenticate(username=username, password=password)
                        # returns a User object if the password is valid for the given username. 
                        # If the password is invalid, authenticate() returns None

                        get_client_last_login(username=username)
                        risk_score = calculate_score_of_trust(ip,username)
                        print("risk score iiiis: ", risk_score)

                        if user is not None:
                                if risk_score < 20:
                                        login(request,user)
                                        return redirect("/")
                                else:
                                        secureCode = generate_secure_code()
                                        # secureCode = signer.sign(str(code))
                                        # secureCode = secureCode.replace(code,"")
                                        # secureCode = base64.b64encode(secureCode)
                                        return redirect('securelogin',username=username, secureCode=secureCode)

                                        securelogin(request,username,secureCode)

                                #trigger_2FA()
                                        #securelogin(request,user)
                                #return HttpResponseRedirect(reverse('login'))
        form = AuthenticationForm()
        return render(request=request, template_name = "corelogin/login.html",context={"form":form})


def securelogin(request,username,secureCode):
        #return render(request, "corelogin/securelogin.html", {'username': username})
        #return redirect("/2fsecure", username=username)


        account_sid = "ACdc092be79e828046c8fdd2ecad1cb644"
        auth_token = "dff722b60ba909558d06dccc3d996e2c"
        client = Client(account_sid, auth_token)

        # global code
        # global signer
        # repack = "{}:{}".format(code,secureCode)
        # secureCode = signer.unsign(repack)
        # secureCode = base64.b64decode(secureCode)
        user = User.objects.get(username=username)
        print(user.email)
        phone = user.logininfo.phonenumber
        print(phone)
        # message = client.messages.create(
        #         body="Your authentication code is {}".format(secureCode),
        #         to="{}".format(phone),
        #         from_="+12025195154")
        # print(message.sid)


        # print(type(code))
        # print("Code is",code)

        ip = get_client_ip(request)
        city = get_client_city(ip)


        if request.method == 'POST':

                print("generated secure code is", secureCode)
                if secureCode is not None:
                        login_data = request.POST.dict()
                        code = login_data.get('Code')
                        print(code)
                        if code == secureCode:
                                print(user.username)
                                user.logininfo.ip = ip
                                user.logininfo.latitude = city["latitude"]
                                user.logininfo.longitude = city["longitude"]
                                user.logininfo.city = city["city"]
                                user.logininfo.save()

                                login(request, user)
                                return redirect("/")

        return render(request, "corelogin/securelogin.html", {'username': username,'secureCode': secureCode})

