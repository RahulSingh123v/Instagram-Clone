import time
from django.core.cache import cache
import redis
from django.conf import settings
from django_redis import get_redis_connection
import structlog

logger = structlog.get_logger()

redis_client = get_redis_connection("default")

class Ratelimiter:

    @staticmethod
    def is_allowed(key: str,limit: int,window_seconds: int) -> bool:
        now = time.time()
        window_start = now-window_seconds

        pipeline = redis_client.pipeline()
         #  remove expired timestamps
        pipeline.zremrangebyscore(key,0,window_start)
       # count current active request
        pipeline.zcard(key)
        # add current request timestamp
        pipeline.zadd(key,{str(now):now})
        # Ensure key expires
        pipeline.expire(key,window_seconds)

        results = pipeline.execute()

        current_count = results[1]
        allowed = current_count < limit

        if not allowed:
            logger.warning("rate_limit_execeded",
                           key=key,
                           current_count=current_count,
                           limit=limit,
                           window_seconds=window_seconds
                           )
            
        return allowed

        



# NAIVE RATE LIMIT USED IN LOGIN,PASSWORD RESET ,ADN PASSWORD RESET CONFIRM
def rate_limit(key: str, limit:int, windows_second: int):

    current = cache.get(key)

    if current is None: 
        cache.set(key,1,timeout=windows_second)
        return True
    if current >= limit:
        return False
    
    cache.incr(key)
    return True

