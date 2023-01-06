from django.core.mail import EmailMessage, send_mail
import threading
import random
from account.models import User 

class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        EmailThread(email).start()


def send_otp(request):
    pass 

def verify_otp(request):
    pass 


def generate_and_send_otp(email):
    otp = random.randint(10000, 99999)
    subject = "One Time Password"
    email_body = f"Yor OTP is {otp}, use this to verify your email"
    email_sent = "" 

    send_mail( subject, email_body, email_sent, [email])

    user = User.objects.get( email = email)
    user.otp = otp
    user.save()

