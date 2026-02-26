from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from backend.services.rate_limit import Ratelimiter
from backend.core.rate_limits import RATE_LIMITS

def rate_limit(endpoint_name: str,identifier_type="ip"):
    def decorator(view_func):
        def wrapper(self,request,*args,**kwargs):
            config = RATE_LIMITS.get(endpoint_name)
            if not config:
                return view_func(self,request,*args,**kwargs)
            
            if identifier_type == "ip":
                identifier = request.META.get("REMOTE_ADDR")
            elif identifier_type == "user":
                identifier = str(request.user.id) if request.user.is_authenticated else request.META.get("REMOTE_ADDR")
            else:
                identifier = request.META.get("REMOTE_ADDR")

            key = f"rl{endpoint_name}:{identifier_type}:{identifier}"

            allowed = Ratelimiter.is_allowed(key,config["limit"],config["window"])

            if not allowed:
                return Response(
                    {"error":"Rate limit exceeded"},
                    status=status.HTTP_429_TOO_MANY_REQUEST
                )

            return view_func(self,request,*args,**kwargs)
        return wrapper
    return decorator