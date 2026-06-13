import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, queue="alerts")
def dispatch_alert(self, alert_id: int) -> None:
    """Placeholder — dispatch an alert notification."""
    logger.info("dispatch_alert called for alert_id=%s", alert_id)
