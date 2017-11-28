from django.contrib.auth import get_user_model

User = get_user_model()


def generate_test_user(username=None, password=None):
    if username is not None:
        username = username
    else:
        username = 'TEST_USER'

    if password is not None:
        password = password
    else:
        password = 'TEST_PASSWORD'

    return User.objects.create_user(username=username,
                                    password=password)
