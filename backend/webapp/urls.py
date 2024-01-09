from django.urls import path

from .views import *  # noqa

urlpatterns = [
    path(".well-known/apple-app-site-association", apple_app_site_association, name="apple-app-site-association"),
    path("registration-begin", registration_begin, name="registration-begin"),
    path("registration-complete", registration_complete, name="registration-complete"),
    path("authenticate-begin", authenticate_begin, name="authenticate-begin"),
    path("authenticate-complete", authenticate_complete, name="authenticate-complete"),
]
