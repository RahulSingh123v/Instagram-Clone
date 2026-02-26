import boto3
import structlog 
from django.conf import settings
from botocore.config import Config 
from botocore.exceptions import ClientError

logger = structlog.get_logger(__name__)

ses_client = boto3.client(
    "ses",
    region_name=settings.AWS_SES_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
)

def send_email(to_email: str,subject:str,body:str,html_body:str=None):
    try:
        resposne = ses_client.send_email(
            source = settings.DEFAULT_FROM_EMAIL,
            destination={
                "toAddresses":[to_email]
            },
            message={
                "subject":{
                    "data":subject,
                    "Charset":"utf-8"
                },
                "body":{
                    "text":{
                        "data":body,
                        "Charset":"utf-8"
                    },
                    "Html":{
                    "data":html_body,
                    "Charset":"utf-8"
                }
                
                }
            }
        )
        logger.info(
            "email sent successfully",
            email=to_email,
            message_id=resposne["MessageId"]
        )
    except ClientError as e:
        logger.error(
            "email_sending_failed",
            email=to_email,
            aws_error=e.response.get("Error",{}),
            exc_info=True
        )
        

