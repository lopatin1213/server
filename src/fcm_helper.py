import firebase_admin
from firebase_admin import credentials, messaging
import os
import json
from typing import Optional

# Путь к вашему JSON-ключу (можно задать через переменную окружения)
SERVICE_ACCOUNT_PATH = os.getenv("FCM_SERVICE_ACCOUNT_PATH",
                                 "C:\\MyProjects\\PythonProject\\vartchat-2b256-firebase-adminsdk-fbsvc-349ef7246c.json")

# Инициализируем Firebase Admin SDK один раз при первом импорте
if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
    firebase_admin.initialize_app(cred)


def send_fcm_push(device_token: str, title: str, body: str, data_payload: Optional[dict] = None) -> bool:
    """
    Отправляет push-уведомление через Firebase Cloud Messaging.
    Возвращает True при успехе, иначе False.
    """
    try:
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body
            ),
            data=data_payload,  # словарь со строковыми значениями (Firebase требует строки)
            token=device_token,
        )
        response = messaging.send(message)
        print(f"FCM отправлено успешно, ID: {response}")
        return True
    except Exception as e:
        print(f"Ошибка FCM: {e}")
        return False