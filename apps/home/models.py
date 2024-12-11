from django.contrib.auth.models import (UserManager, AbstractBaseUser, PermissionsMixin)
from django.db.models import JSONField
from django.db import models
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

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        # Prompt for additional fields
        extra_fields['user_name'] = input("Enter user name: ")

        # Role selection with numeric choices
        roles = [('Investigator', 'Investigator'),
                 ('Forensics Analyst', 'Forensics Analyst'),
                 ('Lab Technician', 'Lab Technician')]

        print("Choose a role:")
        for i, (value, display) in enumerate(roles, start=1):
            print(f"{i}. {display}")

        role_choice = input("Enter the number for the role: ")

        try:
            role_index = int(role_choice) - 1
            if 0 <= role_index < len(roles):
                extra_fields['user_roles'] = roles[role_index][0]
            else:
                raise ValueError("Invalid choice. Please choose a valid role number.")
        except ValueError:
            raise ValueError("Invalid input. Please enter a number corresponding to the role.")

        extra_fields['user_phone'] = input("Enter user phone: ")

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
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_name = models.CharField(max_length=50)
    user_email = models.CharField(max_length=50, unique=True)
    user_roles = models.CharField(max_length=30, choices=[('Investigator', 'Investigator'),
                                                          ('Forensics Analyst', 'Forensics Analyst'),
                                                          ('Lab Technician', 'Lab Technician')])
    user_phone = models.CharField(max_length=15)
    default_folder = models.CharField(max_length=255, null=True, blank=True)
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
        return f"{self.user_name} - {self.user_email}"


class CaseManager(models.Manager):
    def get_queryset(self):
        # Override the default queryset to exclude deleted cases
        return super().get_queryset().filter(is_deleted=False)


class Case(models.Model):
    case_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_cases')
    case_number = models.CharField(max_length=50, null=True, blank=True, unique=True) # Just a unique identifier for the case
    case_member = models.ManyToManyField(User, related_name='case_member', blank=True)
    case_name = models.CharField(max_length=30)
    description = models.TextField(null=True, blank=True) # Just a brief description of the case
    additional_info = JSONField(null=True, blank=True) # Any notes that the user wants to add
    case_is_open = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)  # Soft delete flag
    created_at = models.DateTimeField(auto_now_add=True)
    last_edited_at = models.DateTimeField(auto_now=True)

    objects = CaseManager()  # Default manager excludes deleted cases
    all_objects = models.Manager()  # Includes all cases, even deleted

    def __str__(self):
        return self.case_name

    def delete(self, using=None, keep_parents=False):
        # Override the delete method to perform a soft delete
        self.is_deleted = True
        self.save()


class EvidenceManager(models.Manager):
    def get_queryset(self):
        # Override the default queryset to exclude deleted cases
        return super().get_queryset().filter(is_deleted=False)


class Evidence(models.Model):
    evidence_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    evidence_number = models.CharField(max_length=50, unique=True, null=True, blank=True) # Just a unique identifier for the evidence
    evidence_description = models.TextField(null=True, blank=True)
    evidence_acquired_by = models.ForeignKey(User, on_delete=models.CASCADE, default=None)
    evidence_chain_of_custody = JSONField(default=list, null=True, blank=True)
    evidence_type = models.CharField(max_length=30)
    evidence_status = models.CharField(max_length=30, default=None)
    evidence_acquired_date = models.DateField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)  # Soft delete flag
    created_at = models.DateTimeField(auto_now_add=True)
    last_edited_at = models.DateTimeField(auto_now=True)

    objects = EvidenceManager()  # Default manager excludes deleted cases
    all_objects = models.Manager()  # Includes all cases, even deleted

    def __str__(self):
        return f"{self.evidence_id} - {self.case}"

    def delete(self, using=None, keep_parents=False):
        # Override the delete method to perform a soft delete
        self.is_deleted = True
        self.save()


class Acquisition(models.Model):
    ACQUISITION_TYPE_CHOICES = [
        ('full_file_system', 'Full File System'),
        ('selective_full_file_system', 'Full File System (Selective)'),
        ('logical', 'Logical'),
        ('physical', 'Physical'),
    ]
    ACQUISITION_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('paused', 'Paused'),
        ('cancelled', 'Cancelled'),
        ('failed', 'Failed'),
        ('error', 'Error'),
    ]
    CONNECTION_CHOICES = [
        ('USB', 'USB'),
        ('WiFi', 'WiFi'),
    ]

    acquisition_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    examiner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='acquisitions', null=True, blank=True)
    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE, related_name='acquisitions', null=True, blank=True)
    serial_number = models.CharField(max_length=50, null=True, blank=True)
    connection_type = models.CharField(max_length=10, choices=CONNECTION_CHOICES, default='USB')
    client_ip = models.GenericIPAddressField(protocol='IPv4', blank=True, null=True)
    port = models.PositiveIntegerField(blank=True, null=True)
    acquisition_type = models.CharField(blank=True, null=True, max_length=30, choices=ACQUISITION_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=ACQUISITION_STATUS_CHOICES, default='pending')
    device_id = models.CharField(max_length=50, null=True, blank=True)
    file_name = models.CharField(max_length=255, null=True, blank=True)
    full_path = models.CharField(max_length=255, null=True, blank=True)
    date = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(null=True, blank=True)
    size = models.DecimalField(default=0, max_digits=8, decimal_places=3)
    unique_link = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return f"{self.acquisition_type} Acquisition - {self.status} - {self.date}"


class PhysicalAcquisition(models.Model):
    acquisition = models.OneToOneField(
        Acquisition,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='physical'
    )
    partition_id = models.CharField(max_length=100, null=True, blank=True)
    partition_size = models.BigIntegerField(default=0, null=True, blank=True)
    hash_before_acquisition = models.CharField(max_length=255, null=True, blank=True)
    hash_after_acquisition = models.CharField(max_length=255, null=True, blank=True)
    is_verify_first = models.BooleanField(null=True, blank=True)
    format_type = models.CharField(max_length=10, null=True, blank=True)
    total_transferred_bytes = models.BigIntegerField(default=0, null=True, blank=True)
    acquisition_method = models.CharField(max_length=50, null=True, blank=True)
    source_device = models.CharField(max_length=100, null=True, blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    encryption_status = models.BooleanField(default=False)

    def __str__(self):
        return f"Physical Details for {self.acquisition}"


class SelectiveFullFileSystemAcquisition(models.Model):
    acquisition = models.OneToOneField(
        Acquisition,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='selective_full_file_system'
    )
    selected_applications = JSONField(null=True, blank=True)
    total_records = models.IntegerField(null=True, blank=True)
    hash_result = models.TextField(null=True, blank=True)
    acquisition_tool = models.CharField(max_length=100, null=True, blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Selective FFS Details for {self.acquisition}"


class FullFileSystemAcquisition(models.Model):
    acquisition = models.OneToOneField(
        Acquisition,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='full_file_system'
    )
    file_system_type = models.CharField(max_length=100, null=True, blank=True)
    root_directory = models.CharField(max_length=255, null=True, blank=True)
    total_files = models.IntegerField(null=True, blank=True)
    total_size = models.BigIntegerField(null=True, blank=True)
    hash_result = models.CharField(max_length=64, null=True, blank=True)
    excluded_files = JSONField(null=True, blank=True)
    encryption_status = models.BooleanField(default=False)
    decryption_method = models.CharField(max_length=100, null=True, blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Full File System Details for {self.acquisition}"