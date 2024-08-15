import redis

redis_url = 'redis://localhost:6379/0'

# Initialize the Redis client using the URL from the environment variable
r = redis.from_url(redis_url)

def set_value(key, value):
    r.set(key, value)

def get_value(key):
    value = r.get(key)
    return value.decode('utf-8') if value else None

def delete_value(key):
    r.delete(key)
