from celery import Celery
from app.config import config

celery = Celery(
    'shkeeper',
    broker=f'redis://{config["REDIS_HOST"]}',
    backend=f'redis://{config["REDIS_HOST"]}',
    task_serializer='pickle',
    accept_content=['pickle'],
    result_serializer='pickle',
    result_accept_content=['pickle'],
)

celery.conf.worker_max_tasks_per_child = int(config['CELERY_MAX_TASKS_PER_CHILD'])