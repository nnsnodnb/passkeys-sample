import pickle
from typing import Optional

from django.conf import settings
from django.db import models
from fido2.webauthn import AttestedCredentialData, AuthenticatorData


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
    def authenticate_data(self) -> AuthenticatorData:
        if self._pickle_loads_auth_data is None:
            self._pickle_loads_auth_data = pickle.loads(self.auth_data)
        return self._pickle_loads_auth_data

    @property
    def credential_data(self) -> Optional[AttestedCredentialData]:
        return self.authenticate_data.credential_data
