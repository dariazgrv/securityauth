from django.test import TestCase

# Create your tests here.
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.test import LiveServerTestCase
from selenium.webdriver.chrome.webdriver import WebDriver
from corelogin.models import LoginInfo

from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains


class MySeleniumTests(LiveServerTestCase):

    @classmethod
    def setUp(self):
        self.selenium = webdriver.Chrome(ChromeDriverManager().install())

    @classmethod
    def tearDown(self):
        self.selenium.quit()
        super(MySeleniumTests, self).tearDown

    def test_login_logout(self):
        self.selenium.get('http://127.0.0.1:8000/login/')
        username = self.selenium.find_element_by_id('id_username')
        password = self.selenium.find_element_by_id('id_password')
        button = self.selenium.find_element_by_xpath('//button[text()="Login"]')
        username.send_keys('usertss')
        password.send_keys('parola1234')
        self.selenium.implicitly_wait(10)
        button.click()
        Logoutbutton = self.selenium.find_element_by_xpath('//a[text()="logout"]')
        self.selenium.implicitly_wait(6)
        Logoutbutton.click()
        expected = "Nimic"
        assert self.selenium.title == expected
        self.selenium.implicitly_wait(10)

    # def test_loggedout_homepage(self):
    #     #self.selenium.get('http://127.0.0.1:8000/')
    #     expected = "Home"
    #     assert self.selenium.title == expected
    #     self.selenium.implicitly_wait(10)