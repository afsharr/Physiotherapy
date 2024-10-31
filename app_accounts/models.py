import os
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from imagekit.models import ProcessedImageField
from imagekit.processors import ResizeToFill

class CustomUserManager(BaseUserManager):
    """
    Custom user manager for creating user instances.

    This manager provides methods to create regular users and superusers.
    """

    def create_user(self, username, password=None, email=None, **extra_fields):
        """
        Create and return a regular user with an email, username, and password.

        Args:
            username (str): The username of the user.
            password (str): The password of the user.
            email (str): The email address of the user.
            **extra_fields: Additional fields to be set on the user.

        Raises:
            ValueError: If the username is not provided or if the user is staff and no password is set.

        Returns:
            User: The created user instance.
        """
        if not username:
            raise ValueError('The Username field must be set')

        user = self.model(username=username, email=email, **extra_fields)

        if 'is_staff' in extra_fields and extra_fields['is_staff'] and not password:
            raise ValueError('Admin must have a password')

        if password:
            user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, username, password=None, email=None, **extra_fields):
        """
        Create and return a superuser with the given details.

        Args:
            username (str): The username of the superuser.
            password (str): The password of the superuser.
            email (str): The email address of the superuser.
            **extra_fields: Additional fields to be set on the superuser.

        Returns:
            User: The created superuser instance.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(username, email=email, password=password, **extra_fields)

def user_profile_image_path(instance, filename):
    """
    Generate the file path for the user's profile image.

    Args:
        instance: The instance of the model.
        filename (str): The original filename of the image.

    Returns:
        str: The generated file path for the image.
    """
    ext = filename.split('.')[-1]
    base_filename = f"user_{uuid.uuid4().hex}"
    short_filename = base_filename[:30]
    unique_filename = f"{base_filename}_{short_filename}.{ext}" 

    return os.path.join('profile_images/', unique_filename)

class User(AbstractUser):
    """
    User model extending Django's AbstractUser.

    This model adds a custom email field and uses the custom user manager.

    Attributes:
        email (EmailField): The email address of the user, which is unique and can be null.
    """
    email = models.EmailField(blank=True, null=True, unique=True)
    
    objects = CustomUserManager()

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    REQUIRED_FIELDS = ['first_name', 'last_name',]

class BaseProfile(models.Model):
    """
    Abstract base class for user profiles.

    This class contains fields common to both user profiles and admin profiles.

    Attributes:
        user (OneToOneField): A one-to-one relation with the User model.
        national_id (CharField): The user's national ID, which is unique.
        address (TextField): The address of the user.
        thumbnail (ProcessedImageField): A processed image field for the user's profile thumbnail.
    """
    user = models.OneToOneField('User', on_delete=models.CASCADE)
    national_id = models.CharField(max_length=10, blank=False, null=False, unique=True)
    address = models.TextField(blank=True, null=True)
    thumbnail = ProcessedImageField(
        verbose_name=_('تصویر بندانگشتی'),
        upload_to=user_profile_image_path,
        processors=[ResizeToFill(100, 100)],
        format='WEBP',
        options={'quality': 80},
        blank=True,
        null=True
    )
    
    class Meta:
        abstract = True
                
class UserProfile(BaseProfile):
    """
    User profile model for storing additional user information.

    This model extends the BaseProfile and adds specific fields for user profiles.

    Attributes:
        gender (BooleanField): Indicates the user's gender.
        date_of_birth (DateField): The user's date of birth.
        medical_history (TextField): A history of the user's medical conditions.
        has_osteoporosis (BooleanField): Indicates if the user has osteoporosis.
        has_stroke_history (BooleanField): Indicates if the user has a history of strokes.
        has_multiple_sclerosis (BooleanField): Indicates if the user has multiple sclerosis.
        is_info_self_reported (BooleanField): Indicates if the information is self-reported.
        email_verified (BooleanField): Indicates if the user's email is verified.
    """
    gender = models.BooleanField(choices=((True, _('Male')), (False, _('Female'))), default=1)
    date_of_birth = models.DateField(blank=True, null=False)
    medical_history = models.TextField(blank=True, null=True)
    has_osteoporosis = models.BooleanField(default=False)
    has_stroke_history = models.BooleanField(default=False)
    has_multiple_sclerosis = models.BooleanField(default=False)
    is_info_self_reported = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)

    class Meta:
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')

class AdminProfile(BaseProfile):
    """
    Admin profile model for storing admin-specific information.

    This model extends the BaseProfile and adds specific fields for admin profiles.

    Attributes:
        phone_number (CharField): The admin's phone number, which is unique.
        role (CharField): The role of the admin within the application.
    """
    phone_number = models.CharField(max_length=15, blank=False, null=False, unique=True)
    role = models.CharField(max_length=30, blank=False, null=False)

    class Meta:
        verbose_name = _('Admin Profile')
        verbose_name_plural = _('Admin Profiles')

    REQUIRED_FIELDS = ['role']
