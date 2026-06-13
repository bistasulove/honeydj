import logging

from celery import Task, shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, queue="alerts")  # type: ignore[misc]
def dispatch_alert(self: Task, alert_id: int) -> None:
    """Placeholder — dispatch an alert notification."""
    logger.info("dispatch_alert called for alert_id=%s", alert_id)
