import secrets
import string
from kavenegar import KavenegarAPI, APIException, HTTPException

def generate_verification_code(length=6):
    """تولید یک کد تأیید تصادفی و امن."""
    digits = string.digits  # فقط اعداد
    return ''.join(secrets.choice(digits) for _ in range(length))

api = KavenegarAPI('32627037696A302F706355457839626755393276466E46495351324C325546392F7A7255626F44337558513D')

def send_sms(phone_number, code):
    """ارسال کد تأیید به شماره تلفن با استفاده از API کاوه نگار."""
    params = {
        'sender': '2000500666',  # شماره فرستنده
        'receptor': phone_number,  # شماره گیرنده
        'message': f'کد تأیید شما: {code}'  # متن پیام
    }
    try:
        response = api.sms_send(params)
        return response
    except APIException as e:
        # مدیریت استثناهای API کاوه نگار
        print(f"API Exception: {e}")
    except HTTPException as e:
        # مدیریت استثناهای HTTP
        print(f"HTTP Exception: {e}")
