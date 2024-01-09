import base64
import pickle

import fido2.features
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models, transaction
from django.http.response import JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_safe
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestationObject,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)

from .decorators import request_body_json
from .models import Challenge, Passkey

fido2.features.webauthn_json_mapping.enabled = True

User = get_user_model()
rp = PublicKeyCredentialRpEntity(id=settings.FIDO2_RP_ID, name=settings.FIDO2_SERVER_NAME)


@require_safe
def apple_app_site_association(_):
    return JsonResponse(
        {
            "webcredentials": {
                "apps": [
                    "99649YXF6E.moe.nnsnodnb.Sample",
                ],
            },
        }
    )


@csrf_exempt
@require_POST
@request_body_json
def registration_begin(request):
    if (email := request.json.get("email")) is None:
        return JsonResponse({"error": "email is required"}, status=400)
    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({"error": "invalid email"}, status=400)

    with transaction.atomic():
        lookups = [
            models.Prefetch("passkey_set", Passkey.objects.filter(), to_attr="passkeys"),
        ]
        user, created = User.objects.prefetch_related(*lookups).get_or_create(email=email, defaults={"username": email})
        passkeys = [] if created else [passkey.credential_data for passkey in user.passkeys]

        server = Fido2Server(rp)

        options, state = server.register_begin(
            user=PublicKeyCredentialUserEntity(
                id=user.id.to_bytes(16, "big"),
                name=user.email,
                display_name=user.email,
            ),
            credentials=passkeys,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        Challenge.objects.create(
            challenge=options.public_key["challenge"],
            user=user,
        )

    request.session["fido2_state"] = state

    response = dict(options)

    challenge = base64.b64encode(websafe_decode(response["publicKey"]["challenge"])).decode("ascii")
    excluded_credentials = [base64.b64encode(passkey.credential_id).decode("ascii") for passkey in passkeys]

    return JsonResponse(
        {
            "user_id": response["publicKey"]["user"]["id"],
            "challenge": challenge,
            "excluded_credentials": excluded_credentials,
        }
    )


@csrf_exempt
@require_POST
@request_body_json
def registration_complete(request):
    if (state := request.session.pop("fido2_state")) is None:
        return JsonResponse({"error": f"should POST {reverse('registration-begin')}"}, status=400)
    if (user_id := request.json.get("user_id")) is None:
        return JsonResponse({"error": "user_id is required"}, status=400)
    user_id = int.from_bytes(websafe_decode(user_id), "big")
    if (base64_attestation_object := request.json.get("attestation_object")) is None:
        return JsonResponse({"error": "attestation_object is required"}, status=400)
    attestation_object = base64.b64decode(base64_attestation_object)
    if (base64_client_data_json := request.json.get("client_data_json")) is None:
        return JsonResponse({"error": "client_data_json is required"}, status=400)
    client_data_json = base64.b64decode(base64_client_data_json)

    challenge = get_object_or_404(
        Challenge.objects.select_related("user"),
        challenge=state["challenge"],
        user_id=user_id,
    )

    server = Fido2Server(rp)

    auth_data = server.register_complete(
        state=state,
        client_data=CollectedClientData(client_data_json),
        attestation_object=AttestationObject(attestation_object),
    )

    with transaction.atomic():
        Passkey.objects.create(
            credential_id=websafe_encode(auth_data.credential_data.credential_id),
            auth_data=pickle.dumps(auth_data),
            user=challenge.user,
        )
        challenge.delete()

    return JsonResponse(
        {
            "status": "ok",
        }
    )


@csrf_exempt
@require_POST
@request_body_json
def authenticate_begin(request):
    if (email := request.json.get("email")) is None:
        return JsonResponse({"error": "email is required"}, status=400)

    lookups = [
        models.Prefetch("passkey_set", Passkey.objects.filter(), to_attr="passkeys"),
    ]
    user = get_object_or_404(User.objects.prefetch_related(*lookups), email=email)
    if len(user.passkeys) == 0:
        return JsonResponse({"error": "no passkey"}, status=400)

    server = Fido2Server(rp)

    options, state = server.authenticate_begin(
        credentials=[passkey.credential_data for passkey in user.passkeys],
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    request.session["fido2_state"] = state

    response = dict(options)

    challenge = base64.b64encode(websafe_decode(response["publicKey"]["challenge"])).decode("ascii")
    allow_credentials = [
        base64.b64encode(credential.id).decode("ascii") for credential in options.public_key.allow_credentials
    ]

    return JsonResponse(
        {
            "challenge": challenge,
            "allow_credentials": allow_credentials,
        }
    )


@csrf_exempt
@require_POST
@request_body_json
def authenticate_complete(request):
    if (state := request.session.pop("fido2_state")) is None:
        return JsonResponse({"error": f"should POST {reverse('authenticate-begin')}"}, status=400)
    if (user_id := request.json.get("user_id")) is None:
        return JsonResponse({"error": "user_id is required"}, status=400)
    user_id = int.from_bytes(websafe_decode(base64.b64decode(user_id)), "big")
    if (base64_credential_id := request.json.get("credential_id")) is None:
        return JsonResponse({"error": "credential_id is required"}, status=400)
    credential_id = base64.b64decode(base64_credential_id)
    if (base64_signature := request.json.get("signature")) is None:
        return JsonResponse({"error": "signature is required"}, status=400)
    signature = base64.b64decode(base64_signature)
    if (base64_client_data_json := request.json.get("client_data_json")) is None:
        return JsonResponse({"error": "client_data_json is required"}, status=400)
    client_data_json = base64.b64decode(base64_client_data_json)

    passkey = get_object_or_404(
        Passkey.objects.select_related("user"),
        credential_id=websafe_encode(credential_id),
        user_id=user_id,
    )

    server = Fido2Server(rp)

    server.authenticate_complete(
        state=state,
        credentials=[passkey.credential_data],
        credential_id=credential_id,
        client_data=CollectedClientData(client_data_json),
        auth_data=passkey.authenticate_data,
        signature=signature,
    )

    passkey.sign_count += 1
    passkey.save(update_fields=["sign_count"])

    return JsonResponse(
        {
            "status": "ok",
        }
    )
