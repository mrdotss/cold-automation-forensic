from django import forms
from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from .models import Case, Evidence, User, Acquisition, PhysicalAcquisition, SelectiveFullFileSystemAcquisition, FullFileSystemAcquisition
from django.utils import timezone

# Register your models here.
class UserCreationForm(forms.ModelForm):
    """
    A form for creating new users. Includes all the required
    fields, plus a repeated password.
    """
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ('user_email', 'is_superuser')

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    disabled password hash display field.
    """
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ('user_email', 'password', 'is_superuser')


class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserChangeForm
    add_form = UserCreationForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('user_email',)
    list_filter = ('is_superuser',)
    fieldsets = (
        (None, {'fields': ('user_email', 'password', 'user_name', 'user_roles',
                           'user_phone')}),
        ('Permissions', {'fields': ('is_superuser', 'is_staff')}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('user_email', 'password1', 'password2'),
        }),
    )
    search_fields = ('user_email',)
    ordering = ('user_email',)
    filter_horizontal = ()


# Now register the new UserAdmin...
admin.site.register(User, UserAdmin)
# ... and, since we're not using Django's built-in permissions,
# unregister the Group model from admin.
admin.site.unregister(Group)

class CaseAdmin(admin.ModelAdmin):
    list_display = ['case_name', 'user__user_name']


class EvidenceAdmin(admin.ModelAdmin):
    list_display = ['evidence_number', 'evidence_description', 'case__case_name']


class AcquisitionAdmin(admin.ModelAdmin):
    list_display = ['acquisition_type', 'status',  'unique_link', 'formatted_date']

    @admin.display(description='Date')
    def formatted_date(self, obj):
        # Assuming `date` is a DateTimeField; adjust to local timezone
        return timezone.localtime(obj.date).strftime('%Y-%m-%d %H:%M:%S')


class PhysicalAcquisitionAdmin(admin.ModelAdmin):
    list_display = ['acquisition_id', 'acquisition__status', 'total_transferred_bytes', 'partition_id', 'partition_size']


admin.site.register(Case, CaseAdmin)
admin.site.register(Evidence, EvidenceAdmin)
admin.site.register(Acquisition, AcquisitionAdmin)
admin.site.register(PhysicalAcquisition, PhysicalAcquisitionAdmin)
admin.site.register(SelectiveFullFileSystemAcquisition)
admin.site.register(FullFileSystemAcquisition)