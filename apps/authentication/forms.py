# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model

ROLES = (('Investigator', 'Investigator'),
         ('Forensics Analyst', 'Forensics Analyst'),
         ('Lab Technician', 'Lab Technician')
         )


class LoginForm(forms.Form):
    user_email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                "placeholder": "example@fatechid.com",
                "class": "form-control",
                "autofocus": "true",
            }
        ), required=True)
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "........",
                "class": "form-control pwstrength",
                "data-indicator": "pwindicator",
                "autofocus": "true",
            }
        ))


User = get_user_model()


class SignUpForm(UserCreationForm):
    user_name = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "placeholder": "Mayer Reflino",
                "class": "form-control",
                "autofocus": "true",
            }
        ), required=True)
    user_email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                "placeholder": "example@fatechid.com",
                "class": "form-control",
                "autofocus": "true",
            }
        ), required=True)
    user_roles = forms.ChoiceField(
        widget=forms.Select(
            attrs={
                "class": "form-control selectric"
            }
        ), choices=ROLES, required=True)
    password1 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "........",
                "class": "form-control pwstrength",
                "data-indicator": "pwindicator",
                "autofocus": "true",
            }
        ))
    password2 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "........",
                "class": "form-control",
                "autofocus": "true",
            }
        ))

    class Meta:
        model = User
        fields = ('user_name', 'user_email', 'user_roles', 'password1', 'password2')
