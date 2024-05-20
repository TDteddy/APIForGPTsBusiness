from pydantic import BaseModel

# Pydantic 모델 정의
class Info(BaseModel):
    info: str

class Wnfo(BaseModel):
    fname: str
    info: str