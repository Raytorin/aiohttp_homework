import pydantic
from typing import Optional
from pydantic import v1 as pydantic_v1
import re


def _check_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if re.match(pattern, str(email)):
        return True
    else:
        raise ValueError('incorrect email format')


def _check_text_len(text, max_len, min_len, element_check):
    if len(text) > max_len or len(text) < min_len:
        raise ValueError(f'the {element_check} does not meet the length requirements: {len(text)} > {max_len} or < {min_len}')


def _check_password(password):
    if len(password) < 8:
        raise ValueError('The password is too short. The minimum password length must be 8 symbols.')
    if not any(char.isdigit() for char in password):
        raise ValueError('the password must contain at least one number.')
    if not any(char.isupper() for char in password):
        raise ValueError('The password must contain at least one uppercase letter.')
    if not any(char.islower() for char in password):
        raise ValueError('The password must contain at least one lowercase letter.')


class PostUser(pydantic.BaseModel):
    user_name: str
    user_password: str
    user_email: str

    @pydantic_v1.validator('user_name')
    def validate_username(cls, value):
        if not value.isalpha():
            raise ValueError('the name must contain only letters')
        return value

    @pydantic_v1.validator('user_password')
    def validate_password(cls, value):
        _check_password(value)
        return value

    @pydantic_v1.validator('user_email')
    def validate_email(ctl, value):
        _check_email(value)
        return value


class PatchUser(pydantic.BaseModel):
    user_name: Optional[str]
    user_password: Optional[str]
    user_email: Optional[str]

    @pydantic_v1.validator('user_name')
    def validate_username(cls, value):
        if not value.isalpha():
            raise ValueError('the name must contain only letters')
        return value

    @pydantic_v1.validator('user_password')
    def validate_password(cls, value):
        _check_password(value)
        return value

    @pydantic_v1.validator('user_email')
    def validate_email(ctl, value):
        _check_email(value)
        return value


class PostAdv(pydantic.BaseModel):
    title: str
    description: str

    @pydantic_v1.validator('title')
    def validate_title(ctl, value):
        _check_text_len(str(value), 300, 2, 'title')
        return value

    @pydantic_v1.validator('description')
    def validate_description(ctl, value):
        _check_text_len(str(value), 500, 2, 'description')
        return value


class PatchAdv(pydantic.BaseModel):
    title: Optional[str]
    description: Optional[str]

    @pydantic_v1.validator('title')
    def validate_title(ctl, value):
        _check_text_len(str(value), 300, 2, 'title')
        return value

    @pydantic_v1.validator('description')
    def validate_description(ctl, value):
        _check_text_len(str(value), 500, 2, 'description')
        return value
