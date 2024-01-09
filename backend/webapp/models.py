import pickle

from django.conf import settings
from django.db import models
from webauthn.registration.verify_registration_response import VerifiedRegistration


class Challenge(models.Model):
    challenge = models.CharField(max_length=100)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)


class Passkey(models.Model):
    credential_id = models.CharField(max_length=100)
    auth_data = models.BinaryField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    sign_count = models.IntegerField(default=0)

    _pickle_loads_auth_data = None

    @property
    def authenticate_data(self) -> VerifiedRegistration:
        if self._pickle_loads_auth_data is None:
            self._pickle_loads_auth_data = pickle.loads(self.auth_data)
        return self._pickle_loads_auth_data
