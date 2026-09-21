# Fixture: mass assignment via __all__.
from django import forms
from .models import UserProfile


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        # SEC-08: every column editable, including is_premium and role
        fields = '__all__'
