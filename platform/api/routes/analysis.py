from fastapi import APIRouter

router = APIRouter()

@router.post("/analysis/trigger")
def trigger_analysis():
    # TODO: trigger analysis endpoint
    return {"message": "trigger analysis stub"}
