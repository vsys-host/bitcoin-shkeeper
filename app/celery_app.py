from celery import Celery
from celery.signals import task_prerun, task_postrun
from flask import has_app_context

from app.config import config
from app.db_import import db
from app.logging import logger

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


def _reset_celery_db_session(**_kwargs):
    if not has_app_context():
        return
    try:
        db.session.rollback()
    except Exception:
        logger.warning("Failed to rollback DB session before task", exc_info=True)
        try:
            db.session.remove()
        except Exception:
            pass


def _remove_celery_db_session(**_kwargs):
    """Close the worker Session so the next task does not reuse a dead connection."""
    if not has_app_context():
        return
    try:
        db.session.remove()
    except Exception:
        logger.warning("Failed to remove DB session after task", exc_info=True)


task_prerun.connect(_reset_celery_db_session)
task_postrun.connect(_remove_celery_db_session)