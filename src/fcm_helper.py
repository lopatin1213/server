import firebase_admin
from firebase_admin import credentials, messaging
import os
import logging
from typing import Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_ACCOUNT_PATH = os.getenv(
    "FCM_SERVICE_ACCOUNT_PATH",
    "C:\\MyProjects\\PythonProject\\vartchat-2b256-firebase-adminsdk-fbsvc-349ef7246c.json",
)

if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
    firebase_admin.initialize_app(cred)


def send_fcm_push(
        device_token: str,
        title: str,
        body: str,
        data_payload: Optional[dict] = None,
) -> Tuple[bool, bool]:
    """
    Возвращает (success, connection_failed):
      - (True,  False) — отправлено
      - (False, True)  — не смогли связаться с FCM (сеть, конфиг, SDK). Токен НЕ удалять.
      - (False, False) — FCM ответил ошибкой (включая невалидный токен). Токен УДАЛИТЬ.
    """
    if not device_token or not isinstance(device_token, str) or not device_token.strip():
        logger.error("FCM: пустой или нестроковый токен -> удаляем")
        return (False, False)

    if data_payload is not None:
        data_payload = {k: (v if isinstance(v, str) else str(v)) for k, v in data_payload.items()}

    try:
        message = messaging.Message(
            notification=messaging.Notification(title=title, body=body),
            data=data_payload,
            token=device_token,
        )
        response = messaging.send(message)
        logger.info(f"FCM отправлено успешно, ID: {response}")
        return (True, False)

    except (
            messaging.UnregisteredError,
            messaging.SenderIdMismatchError,
            ValueError,  # "Message.token must be a non-empty string"
    ) as e:
        logger.error(f"FCM отклонил токен ({type(e).__name__}): {e}")
        return (False, False)

    except Exception as e:
        # Всё остальное: сеть, квоты, конфиг — считаем проблемой подключения.
        # НО если в тексте явно видно notregistered/invalid — это точно отказ по токену.
        low = str(e).lower()
        if "notregistered" in low or "not registered" in low or "unregistered" in low \
                or "invalidregistration" in low or "invalid token" in low \
                or "must be a non-empty string" in low or "senderidmismatch" in low:
            logger.error(f"FCM отклонил токен ({type(e).__name__}): {e}")
            return (False, False)

        logger.error(f"FCM недоступен ({type(e).__name__}): {e}")
        return (False, True)