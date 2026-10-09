from celery import Celery

celery_app = Celery("automata_worker", broker="redis://localhost:6379/0")

@celery_app.task
def analyze_firmware(firmware_id: str):
    # stub
    pass
