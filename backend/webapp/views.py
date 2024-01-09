import base64
import pickle
import secrets

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
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
)
from webauthn import base64url_to_bytes, verify_registration_response, verify_authentication_response
from webauthn.helpers import bytes_to_base64url

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
        passkeys = [] if created else [passkey.authenticate_data for passkey in user.passkeys]

        encoded_challenge = base64.b64encode(secrets.token_bytes(32)).decode("ascii")

        state = {
            "challenge": encoded_challenge,
        }

        challenge = Challenge.objects.create(
            challenge=encoded_challenge,
            user=user,
        )

    request.session["fido2_state"] = state
    excluded_credentials = [base64.b64encode(passkey.credential_id).decode("ascii") for passkey in passkeys]

    return JsonResponse(
        {
            "user_id": base64.b64encode(user.id.to_bytes(16, "big")).decode("ascii"),
            "challenge": challenge.challenge,
            "excluded_credentials": excluded_credentials,
        }
    )


@csrf_exempt
@require_POST
@request_body_json
def registration_complete(request):
    if (state := request.session.pop("fido2_state")) is None:
        return JsonResponse({"error": f"should POST {reverse('registration-begin')}"}, status=400)
    if (base64_user_id := request.json.get("user_id")) is None:
        return JsonResponse({"error": "user_id is required"}, status=400)
    user_id = base64.b64decode(base64_user_id)
    user_id = int.from_bytes(user_id, "big")
    if (base64_credential_id := request.json.get("credential_id")) is None:
        return JsonResponse({"error": "credential_id is required"}, status=400)
    credential_id = base64.b64decode(base64_credential_id)
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

    credential = {
        "id": bytes_to_base64url(credential_id),
        "rawId": bytes_to_base64url(credential_id),
        "response": {
            "attestationObject": bytes_to_base64url(attestation_object),
            "clientDataJSON": bytes_to_base64url(client_data_json),
        },
        "type": "public-key",
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }

    registration_verification = verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(challenge.challenge),
        expected_origin=f"https://{settings.FIDO2_RP_ID}",
        expected_rp_id=settings.FIDO2_RP_ID,
        require_user_verification=True,
    )

    with transaction.atomic():
        Passkey.objects.create(
            credential_id=bytes_to_base64url(registration_verification.credential_id),
            auth_data=pickle.dumps(registration_verification),
            user=challenge.user,
        )
        challenge.delete()
        request.session["fido2_state"] = None

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

    encoded_challenge = base64.b64encode(secrets.token_bytes(32)).decode("ascii")

    state = {
        "challenge": encoded_challenge,
    }

    request.session["fido2_state"] = state
    allow_credentials = [
        base64.b64encode(passkey.authenticate_data.credential_id).decode("ascii") for passkey in user.passkeys
    ]

    return JsonResponse(
        {
            "challenge": encoded_challenge,
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
    user_id = base64.b64decode(base64.b64decode(user_id))
    user_id = int.from_bytes(user_id, "big")
    if (base64_credential_id := request.json.get("credential_id")) is None:
        return JsonResponse({"error": "credential_id is required"}, status=400)
    credential_id = base64.b64decode(base64_credential_id)
    if (base64_authenticator_data := request.json.get("authenticator_data")) is None:
        return JsonResponse({"error": "authenticator_data is required"}, status=400)
    authenticator_data = base64.b64decode(base64_authenticator_data)
    if (base64_signature := request.json.get("signature")) is None:
        return JsonResponse({"error": "signature is required"}, status=400)
    signature = base64.b64decode(base64_signature)
    if (base64_client_data_json := request.json.get("client_data_json")) is None:
        return JsonResponse({"error": "client_data_json is required"}, status=400)
    client_data_json = base64.b64decode(base64_client_data_json)

    passkey = get_object_or_404(
        Passkey.objects.select_related("user"),
        credential_id=bytes_to_base64url(credential_id),
        user_id=user_id,
    )

    credential = {
        "id": bytes_to_base64url(credential_id),
        "rawId": bytes_to_base64url(credential_id),
        "response": {
            "authenticatorData": bytes_to_base64url(authenticator_data),
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "signature": bytes_to_base64url(signature),
        },
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
    }

    authentication_verification = verify_authentication_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(state["challenge"]),
        expected_rp_id=settings.FIDO2_RP_ID,
        expected_origin=f"https://{settings.FIDO2_RP_ID}",
        credential_public_key=passkey.authenticate_data.credential_public_key,
        credential_current_sign_count=passkey.sign_count,
        require_user_verification=True,
    )

    with transaction.atomic():
        passkey.sign_count = authentication_verification.new_sign_count
        passkey.save(update_fields=["sign_count"])
        request.session["fido2_state"] = None

    return JsonResponse(
        {
            "status": "ok",
        }
    )
