def send_to_mail(to: str = "", subject: str = "", body: str = ""):
    print(
        f"ссылка для сброса пароля: /auth/reset/coniform?token={body}\n отправленно на {to}"
    )
