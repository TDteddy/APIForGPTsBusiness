import base64
import json
import os
import urllib
import pybase64
from httpx import AsyncClient
from fastapi import FastAPI, HTTPException
import uvicorn
import models
import datetime
import dotenv
import requests
import hmac
import hashlib
import time
import bcrypt

#.env 파일을 읽어서 환경변수로 설정
dotenv.load_dotenv()

#cors
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import FileResponse

app = FastAPI()

# CORS 설정 추가
app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_methods=["*"],
  allow_headers=["*"],
  allow_credentials=True
)
information_filemap_root = "./filemap/informaiton.txt"
prompt_filemap_root = "./filemap/prompt.txt"

NAVER_CLIENT_ID = os.getenv("NAVER_CLIENT_ID")
NAVER_CLIENT_SECRET = os.getenv("NAVER_CLIENT_SECRET")

C_NAVER_CLIENT_ID = os.getenv("C_NAVER_CLIENT_ID")
C_NAVER_CLIENT_SECRET = os.getenv("C_NAVER_CLIENT_SECRET")

API_SECRET = os.getenv("API_SECRET")
CUSTOMER_ID = os.getenv("CUSTOMER_ID")
API_KEY = os.getenv("API_KEY")

BASE_URL = "https://api.searchad.naver.com"

@app.get("/read_information")
async def read_information():
    try:
        with open(information_filemap_root, "rt", encoding="UTF8") as file:
            data = file.read()
        return {"information": data}
    except FileNotFoundError:
        return {"error": "File not found"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/write_information")
async def write_information(info_data: models.Info):
    info_content = info_data.info
    try:
        with open(information_filemap_root, "at", encoding="UTF8") as file:
            file.write(info_content)
        return {"status": "success"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/read_prompt")
async def read_prompt():
    try:
        with open(prompt_filemap_root, "rt", encoding="UTF8") as file:
            data = file.read()
        return {"information": data}
    except FileNotFoundError:
        return {"error": "File not found"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/write_prompt")
async def write_prompt(info_data: models.Info):
    info_content = info_data.info
    try:
        with open(prompt_filemap_root, "at", encoding="UTF8") as file:
            file.write(info_content)
        return {"status": "success"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/read_information_file")
async def read_information_file(keyvalue: str):
    filename = keyvalue
    try:
        information_filemap = {}
        with open(information_filemap_root, "rt", encoding="UTF8") as file:
            data = file.read().split("\n")
            for i in data:
                if i:
                    temp = i.split(":")
                    information_filemap[temp[0]] = temp[1]
        if filename not in information_filemap:
            raise FileNotFoundError(f"File {filename} not found in mapping.")
        data = open(information_filemap[filename], "rt", encoding="UTF8").read()
        print(information_filemap[filename])
        return {"information": data}
    except FileNotFoundError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

@app.get("/read_prompt_file")
async def read_information_file(keyvalue: str):
    filename = keyvalue
    try:
        prompt_filemap = {}
        with open(prompt_filemap_root, "rt", encoding="UTF8") as file:
            data = file.read().split("\n")
            for i in data:
                if i:
                    temp = i.split(":")
                    prompt_filemap[temp[0]] = temp[1]
        if filename not in prompt_filemap:
            raise FileNotFoundError(f"File {filename} not found in mapping.")
        data = open(prompt_filemap[filename], "rt", encoding="UTF8").read()
        print(prompt_filemap[filename])
        return {"information": data}
    except FileNotFoundError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

@app.post("/write_information_file")
async def update_information_file(info_data: models.Wnfo):
    filename = info_data.fname
    info_content = info_data.info
    try:
        information_filemap = {}
        with open(information_filemap_root, "rt", encoding="UTF8") as file:
            data = file.read().split("\n")
            for i in data:
                if i:
                    temp = i.split(":")
                    information_filemap[temp[0]] = temp[1]
        if filename not in information_filemap:
            raise FileNotFoundError(f"File {filename} not found in mapping.")
        with open(information_filemap[filename], "at", encoding="UTF8") as file:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            data = f"\n\n\n{now} 수정\n{info_content}"
            file.write(data)
        return {"status": "success"}
    except Exception as e:
        return {"error": str(e)}



def generate_signature(api_secret: str, timestamp: str, http_method: str, request_uri: str) -> str:
    message = "{}.{}.{}".format(timestamp, http_method, request_uri)
    hash = hmac.new(bytes(api_secret, "utf-8"), bytes(message, "utf-8"), hashlib.sha256)
    hash.hexdigest()
    return base64.b64encode(hash.digest())

def generate_hash_base64(clid: str, clsecret: str, timestamp: str):
    password = clid + "_" + timestamp
    hashed = bcrypt.hashpw(password.encode('utf-8'), clsecret.encode('utf-8'))
    encoded = pybase64.standard_b64encode(hashed).decode('utf-8')  # 해시 값을 base64로 인코딩
    return encoded

@app.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    try:
        timestamp = str(int(time.time() * 1000))
        request_uri = f"/ncc/campaigns/{campaign_id}"
        signature = generate_signature(API_SECRET, timestamp, "GET", request_uri)

        headers = {
            "X-Timestamp": timestamp,
            "X-API-KEY": API_KEY,
            "X-Customer": CUSTOMER_ID,
            "X-Signature": signature
        }

        full_url = BASE_URL + request_uri
        response = requests.get(full_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/campaigns")
async def get_campaign_list():
    try:
        timestamp = str(int(time.time() * 1000))
        request_uri = "/ncc/campaigns"
        signature = generate_signature(API_SECRET, timestamp, "GET", request_uri)

        headers = {
            "X-Timestamp": timestamp,
            "X-API-KEY": API_KEY,
            "X-Customer": CUSTOMER_ID,
            "X-Signature": signature
        }

        full_url = BASE_URL + request_uri
        response = requests.get(full_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stat")
async def get_stat_report(id: str, startdate: str, enddate: str):
    try:
        fields = '["impCnt","clkCnt","salesAmt","ctr","cpc","avgRnk","ccnt","recentAvgRnk","recentAvgCpc","pcNxAvgRnk","mblNxAvgRnk","crto","convAmt","ror","cpConv","viewCnt"]'
        timerange = '{"since":"' + startdate + '", "until":"' + enddate + '"}'

        print(fields)
        print(timerange)

        payload = {
            'id': id,
            'fields': fields,
            'timeRange': timerange,
        }
        timestamp = str(int(time.time() * 1000))
        request_uri = "/stats"
        signature = generate_signature(API_SECRET, timestamp, "GET", request_uri)

        headers = {
            "X-Timestamp": timestamp,
            "X-API-KEY": API_KEY,
            "X-Customer": CUSTOMER_ID,
            "X-Signature": signature
        }

        full_url = BASE_URL + request_uri
        response = requests.get(full_url, headers=headers, params=payload)
        print(response.json())
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/getkeywordinfo")
async def get_keyword_info(keyword: str):
    try:
        timestamp = str(int(time.time() * 1000))
        request_uri = "/keywordstool"
        signature = generate_signature(API_SECRET, timestamp, "GET", request_uri)

        headers = {
            "X-Timestamp": timestamp,
            "X-API-KEY": API_KEY,
            "X-Customer": CUSTOMER_ID,
            "X-Signature": signature
        }

        payload = {
            "hintKeywords": keyword,
            "showDetail": "1"
        }

        full_url = BASE_URL + request_uri
        response = requests.get(full_url, headers=headers, params=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/search/navershop")
async def search_shop(query: str):
    try:
        encText = urllib.parse.quote(query)
        url = "https://openapi.naver.com/v1/search/shop.json?query=" + encText +"&display=30" # JSON 결과
        headers = {
            "X-Naver-Client-Id": NAVER_CLIENT_ID,
            "X-Naver-Client-Secret": NAVER_CLIENT_SECRET
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/shop/gettoken")
async def get_token():
    try:
        url = "https://api.commerce.naver.com/external/v1/oauth2/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        timestamp = str(int(time.time() * 1000))
        datta = "client_id=2wUxkUa52hDs2KANGAAwkK&timestamp="+timestamp+"&client_secret_sign="+str(generate_hash_base64("2wUxkUa52hDs2KANGAAwkK", "$2a$04$Ft7sTzGhIK0y2qkkEfxuIu", timestamp))+"&type=SELF"
        response = requests.post(url, headers=headers, data=datta)
        print(response.json())
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/shop/customer_review/{tokenno}")
async def get_customer_review(tokenno: str, startSearchDate: str, endSearchDate: str):
    try:
        url = "https://api.commerce.naver.com/external/v1/pay-user/inquiries"
        headers = {
            "Authorization": f"Bearer {tokenno}"
        }
        payload = {
            "startSearchDate": startSearchDate,
            "endSearchDate": endSearchDate
        }
        response = requests.get(url, headers=headers, params=payload)
        print(response.json())
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/shop/add_replyto_review/{tokenno}")
async def add_reply_to_review(tokenno: str, inquiryNo: str, replyContent: str):
    try:
        url = f"https://api.commerce.naver.com/external/v1/pay-merchant/inquiries/{inquiryNo}/answer"
        headers = {
            "Authorization": f"Bearer {tokenno}",
        }
        payload = {
            "replyContent": replyContent
        }
        response = requests.post(url, headers=headers, data=payload)
        print(response.json())
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/colormind")
async def get_colormind(rgbs: str):
    # rgbs 문자열을 Python 객체로 변환
    try:
        rgbs_list = json.loads(rgbs)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid rgbs format")

    try:
        url = "http://colormind.io/api/"
        payload = {
            "model": "default",
            "input": rgbs_list  # 수정된 부분
        }
        # params 대신 json 사용
        response = requests.post(url, json=payload)
        response.raise_for_status()  # 오류 검사를 먼저 함
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/naverdatalab")
async def get_naver_datalab(startdate: str, enddate: str):
    catelist = [{
        "name": "스킨케어","param": ["100000913"]
        },
        {
            "name": "바디케어", "param": ["100000920"]
        },
        {
            "name": "헤어케어", "param": ["100000921"]
        }]
    jsoncatelist = json.dumps(catelist)
    try:
        url = "https://openapi.naver.com/v1/datalab/shopping/categories"
        headers = {
            "X-Naver-Client-Id": NAVER_CLIENT_ID,
            "X-Naver-Client-Secret": NAVER_CLIENT_SECRET
        }
        payload = {
            "startDate": startdate,
            "endDate": enddate,
            "timeUnit": "date",
            "category": catelist,
        }
        response = requests.post(url, headers=headers, json=payload)
        print(response.json())
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        raise HTTPException(status_code=response.status_code, detail=str(http_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/get_access_token")
async def get_access_token():
    try:
        with open("metatoken.txt", "rt", encoding="UTF8") as file:
            data = file.read()
        return {"token": data}
    except FileNotFoundError:
        return {"error": "File not found"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/update_access_token")
async def update_access_token(token: str):
    try:
        with open("metatoken.txt", "wt", encoding="UTF8") as file:
            file.write(token)
        return {"status": "success"}
    except Exception as e:
        return {"error": str(e)}
@app.get("/readrank")
async def read_rank():
    try:
        with open("rank.txt", "rt", encoding="UTF8") as file:
            data = file.read()
        return {"rank": data}
    except FileNotFoundError:
        return {"error": "File not found"}
    except Exception as e:
        return {"error": str(e)}
@app.post("/writerank")
async def write_rank(info_data: models.Info):
    info_content = info_data.info
    try:
        with open("rank.txt", "at", encoding="UTF8") as file:
            file.write(info_content+"\n")
        return {"status": "success"}
    except Exception as e:
        return {"error": str(e)}

# 애플리케이션 실행 설정
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, ssl_keyfile="private.key", ssl_certfile="certificate.crt", log_level="debug")

