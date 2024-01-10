import json
from functools import wraps

from django.http.response import JsonResponse


def request_body_json(func):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            try:
                data = json.loads(request.body)
                setattr(request, "json", data)
                return view_func(request, *args, **kwargs)
            except json.decoder.JSONDecodeError as e:
                return JsonResponse({"error": str(e)}, status=400)

        return wrapper

    return wraps(func)(decorator(func))
