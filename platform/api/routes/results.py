from fastapi import APIRouter

router = APIRouter()

@router.get("/results/{result_id}")
def get_results(result_id: str):
    # TODO: retrieve results endpoint
    return {"message": "retrieve results stub", "id": result_id}
