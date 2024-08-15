from django.contrib.auth.models import (UserManager, AbstractBaseUser, PermissionsMixin)
from django.db import models
from django.db.models import JSONField
import uuid
import os


def file_path_document(instance, filename):
    """
    This function will generate a unique file name for the document

    :param instance: The instance of the model
    :param filename: The name of the file
    :return: The path to the document
    """
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return os.path.join('files/', filename)


class CustomUserManager(UserManager):
    def _create_user(self, user_email, password, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not user_email:
            raise ValueError("You have not provided a valid e-mail address.")

        user_email = self.normalize_email(user_email)
        user = self.model(user_email=user_email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, user_email=None, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(user_email, password, **extra_fields)

    def create_user(self, user_email=None, password=None, **extra_fields):
        """
        Creates and saves a user with the given email and password.
        """
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)

        user = self.create_user(
            user_email,
            password=password,
            **extra_fields
        )

        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_name = models.CharField(max_length=50)
    user_email = models.CharField(max_length=50, unique=True)
    user_roles = models.CharField(max_length=30, choices=[('Investigator', 'Investigator'),
                                                          ('Forensics Analyst', 'Forensics Analyst'),
                                                          ('Lab Technician', 'Lab Technician')])
    user_phone = models.CharField(max_length=15)
    created_at = models.DateTimeField(auto_now_add=True)
    last_edited_at = models.DateTimeField(auto_now=True)

    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    last_login = models.DateTimeField(blank=True, null=True)

    objects = CustomUserManager()
    USERNAME_FIELD = 'user_email'
    EMAIL_FIELD = 'user_email'
    REQUIRED_FIELDS = []

    def has_perm(self, perm, obj=None):
        """
        Does the user have a specific permission?
        Simplest possible answer: Yes, always
        """
        return True

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def get_short_name(self):
        return self.user_name.split(' ')[0] or self.user_name.split('@')[0]

    def __str__(self):
        return self.user_name


class Case(models.Model):
    case_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    case_member = models.ManyToManyField(User, related_name='case_member')
    case_name = models.CharField(max_length=30)
    case_is_open = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_edited_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.case_name


class Log(models.Model):
    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    log_action = models.CharField(max_length=10)
    log_data_type = models.CharField(max_length=20)
    log_old_value = models.CharField(max_length=255)
    log_new_value = models.CharField(max_length=255)
    caf_log_created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.log_id


class Evidence(models.Model):
    evidence_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    evidence_description = models.CharField(max_length=255, null=True, blank=True)
    evidence_acquired_by = models.ForeignKey(User, on_delete=models.CASCADE, default=None)
    evidence_chain_of_custody = JSONField(default=list, null=True, blank=True)
    evidence_type = models.CharField(max_length=30)
    evidence_status = models.CharField(max_length=30, default=None)
    evidence_file_location = models.CharField(max_length=255, null=True, blank=True)
    evidence_acquired_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_edited_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.evidence_id} - {self.case}"


class Acquisition(models.Model):
    acquisition_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE, related_name='acquisitions', null=True, blank=True)
    acquisition_status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('progress', 'Progress'),
        ('completed', 'Completed'),
        ('paused', 'Paused'),
        ('failed', 'Failed'),
        ('error', 'Error')  # If there was an error during acquisition
    ], default='pending')
    acquisition_device_id = models.CharField(max_length=50, null=True, blank=True)
    acquisition_file_name = models.CharField(max_length=255, null=True, blank=True)
    acquisition_full_path = models.CharField(max_length=255, null=True, blank=True)
    acquisition_client_ip = models.CharField(max_length=15, blank=True, null=True)
    acquisition_custom_port = models.CharField(max_length=5, blank=True, null=True)
    acquisition_partition_id = models.CharField(max_length=100, null=True, blank=True)
    acquisition_total_transferred_bytes = models.BigIntegerField(default=0, null=True, blank=True)
    acquisition_size = models.BigIntegerField(default=0, null=True, blank=True)
    acquisition_size_template = models.DecimalField(max_digits=10, decimal_places=2, default=0, null=True, blank=True)
    acquisition_unique_link = models.CharField(max_length=255, unique=True)
    acquisition_type = models.CharField(max_length=50, null=True, blank=True)
    acquisition_date = models.DateTimeField(auto_now_add=True)
    acquisition_last_active = models.DateTimeField(null=True, blank=True)
    acquisition_hash = models.CharField(max_length=64, blank=True, null=True)
    acquisition_hash_verify = models.CharField(max_length=64, blank=True, null=True)
    acquisition_is_verify_first = models.BooleanField(null=True, blank=True)

    def __str__(self):
        return f"{self.acquisition_status} - {self.acquisition_unique_link}"
