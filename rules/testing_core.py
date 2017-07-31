from django.contrib.auth import get_user_model

User = get_user_model()


def generate_test_user():
    return User.objects.create_user(username='RULETESTER',
                                    password='RULETESTERPASSWORD')
