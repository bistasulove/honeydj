import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, queue="enrichment")
def enrich_event(self, event_id: int) -> None:
    """Placeholder — enrich a captured honeypot event."""
    logger.info("enrich_event called for event_id=%s", event_id)
