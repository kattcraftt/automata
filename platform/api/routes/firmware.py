from fastapi import APIRouter

router = APIRouter()

@router.post("/firmware/upload")
def upload_firmware():
    # TODO: upload firmware endpoint
    return {"message": "upload firmware stub"}
