import firebase_admin
import logging
import os
from firebase_admin import credentials, messaging
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

    # Формируем data-payload
    final_data = data_payload.copy() if data_payload else {}
    final_data["title"] = title
    final_data["body"] = body

    # Убеждаемся, что все значения строковые (требование FCM)
    final_data = {k: (v if isinstance(v, str) else str(v)) for k, v in final_data.items()}

    try:
        message = messaging.Message(
            data=final_data,
            token=device_token,
            android=messaging.AndroidConfig(
                priority='high',  # Важно для data-only!
            ),
        )
        response = messaging.send(message)
        logger.info(f"FCM (data-only) отправлено успешно, ID: {response}")
        return (True, False)

    except (
            messaging.UnregisteredError,
            messaging.SenderIdMismatchError,
            ValueError,
    ) as e:
        logger.error(f"FCM отклонил токен ({type(e).__name__}): {e}")
        return (False, False)

    except Exception as e:
        low = str(e).lower()
        if "notregistered" in low or "not registered" in low or "unregistered" in low \
                or "invalidregistration" in low or "invalid token" in low \
                or "must be a non-empty string" in low or "senderidmismatch" in low:
            logger.error(f"FCM отклонил токен ({type(e).__name__}): {e}")
            return (False, False)

        logger.error(f"FCM недоступен ({type(e).__name__}): {e}")
        return (False, True)