from rest_framework import serializers
from .models import UserProfile, AdminProfile
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class SMSLoginSerializer(serializers.Serializer):
    """
    Serializer for SMS login.

    Fields:
        username (str): Required username of the user.
        verification_code (str): Required verification code sent to the user.
        phone_number (str): Optional phone number for the user.

    Validation:
        If the user does not exist, a new user will be created with `is_active` set to False.
    """
    username = serializers.CharField(required=True)
    verification_code = serializers.CharField(required=True)
    phone_number = serializers.CharField(required=False)

    def validate(self, data):
        username = data['username']
        user = User.objects.filter(username=username).first()

        if not user:
            user = User(username=username, is_active=False)
            user.save()
        
        data['user'] = user
        return data

class PasswordLoginSerializer(serializers.Serializer):
    """
    Serializer for password login.

    Fields:
        username (str): Required username of the user.
        password (str): Required password of the user.

    Validation:
        Checks if the user exists, if the account is active, and if the password is correct.
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, data):
        user = User.objects.filter(username=data['username']).first()
        if not user:
            raise serializers.ValidationError("کاربری با این نام کاربری پیدا نشد.")
        if not user.is_active:
            raise serializers.ValidationError("شما دسترسی لازم برای ورود ندارید.")
        if not user.check_password(data['password']):
            raise serializers.ValidationError("پسورد نامعتبر است.")
        data['user'] = user
        return data
    
class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile.

    Fields:
        national_id (str): User's national ID.
        date_of_birth (date): User's date of birth.
        gender (bool): User's gender.
        address (str): User's address.
        medical_history (str): User's medical history.
        has_osteoporosis (bool): Indicates if the user has osteoporosis.
        has_stroke_history (bool): Indicates if the user has a history of strokes.
        has_multiple_sclerosis (bool): Indicates if the user has multiple sclerosis.
        is_info_self_reported (bool): Indicates if the information is self-reported.
    """
    class Meta:
        model = UserProfile
        fields = ['national_id', 'date_of_birth', 'gender', 'address', 
                  'medical_history', 'has_osteoporosis', 
                  'has_stroke_history', 'has_multiple_sclerosis', 
                  'is_info_self_reported']

class UserProfileCreateSerializer(UserProfileSerializer):
    """
    Serializer for creating a user profile.

    Inherits from UserProfileSerializer and adds:
        user_id (int): ID of the user to associate with the profile.
    """
    user_id = serializers.IntegerField()

    class Meta(UserProfileSerializer.Meta):
        fields = UserProfileSerializer.Meta.fields + ['user_id']

class UpdateUserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user profiles.

    Fields:
        email (str): User's email (optional).
        first_name (str): User's first name (optional).
        last_name (str): User's last name (optional).
        national_id (str): User's national ID (required).
        date_of_birth (date): User's date of birth (required).
        gender (bool): User's gender (required).
    """
    email = serializers.EmailField(source='user.email', required=False, allow_blank=True)
    first_name = serializers.CharField(source='user.first_name', required=False, allow_blank=True)
    last_name = serializers.CharField(source='user.last_name', required=False, allow_blank=True)
    national_id = serializers.CharField(required=True)
    date_of_birth = serializers.DateField(required=True)
    gender = serializers.BooleanField(required=True)

    class Meta:
        model = UserProfile
        fields = [
            'national_id', 
            'date_of_birth', 
            'gender', 
            'address', 
            'medical_history', 
            'has_osteoporosis', 
            'has_stroke_history', 
            'has_multiple_sclerosis', 
            'is_info_self_reported', 
            'email', 
            'first_name', 
            'last_name'
        ]

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        
        if user_data:
            user = instance.user
            user.first_name = user_data.get('first_name', user.first_name)
            user.last_name = user_data.get('last_name', user.last_name)
            user.email = user_data.get('email', user.email)
            user.save()

        for attr, value in validated_data.items():
            if attr in ['national_id', 'date_of_birth', 'gender']:
                if value is None or value == '':
                    raise serializers.ValidationError({attr: f"{attr} field is required."})
            setattr(instance, attr, value if value is not None and value != '' else None)
        instance.save()

        return instance
      
class CreateAdminProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for creating an admin profile.

    Fields:
        groups (list): List of groups to which the user belongs (optional).
        phone_number (str): Admin's phone number (required).
        role (str): Admin's role (required).
        national_id (str): Admin's national ID (required).
        address (str): Admin's address (required).
        password (str): Admin's password (required).

    Validation:
        Creates a user and an associated admin profile.
    """
    groups = serializers.ListField(
        child=serializers.PrimaryKeyRelatedField(queryset=Group.objects.all()),
        required=False
    )
    
    phone_number = serializers.CharField(required=True)
    role = serializers.CharField(required=True)
    national_id = serializers.CharField(required=True)
    address = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'groups', 'phone_number', 'role', 'national_id', 'address', 'password']

    def create(self, validated_data):
        groups_data = validated_data.pop('groups', [])
        user = User.objects.create_user(
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
            password=validated_data['password'],
            is_staff=True
        )
        
        AdminProfile.objects.create(
            user=user,
            phone_number=validated_data['phone_number'],
            role=validated_data['role'],
            national_id=validated_data['national_id'],
            address=validated_data['address']
        )

        if groups_data:
            user.groups.set(groups_data)

        return user

class UpdateAdminProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for updating an admin profile.

    Fields:
        groups (list): List of groups to which the user belongs (optional).
        phone_number (str): Admin's phone number (required).
        role (str): Admin's role (required).
        national_id (str): Admin's national ID (required).
        address (str): Admin's address (required).

    Validation:
        Updates both the user and the admin profile information.
    """
    groups = serializers.ListField(
        child=serializers.PrimaryKeyRelatedField(queryset=Group.objects.all()),
        required=False
    )

    phone_number = serializers.CharField(required=True)
    role = serializers.CharField(required=True)
    national_id = serializers.CharField(required=True)
    address = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'groups', 'phone_number', 'role', 'national_id', 'address']

    def update(self, instance, validated_data):
        groups_data = validated_data.pop('groups', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        admin_profile = instance.adminprofile
        for attr, value in validated_data.items():
            setattr(admin_profile, attr, value)
        admin_profile.save()

        if groups_data is not None:
            instance.groups.set(groups_data)

        return instance
      
class UserProfileThumbnailSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile thumbnail.

    Fields:
        thumbnail (ImageField): Thumbnail image for the user profile.
    """
    class Meta:
        model = UserProfile
        fields = ['thumbnail']

class AdminProfileThumbnailSerializer(serializers.ModelSerializer):
    """
    Serializer for admin profile thumbnail.

    Fields:
        thumbnail (ImageField): Thumbnail image for the admin profile.
    """
    class Meta:
        model = AdminProfile
        fields = ['thumbnail']

class CreatePasswordSerializer(serializers.Serializer):
    """
    Serializer for creating a new password for a user.
    
    Attributes:
        password (str): The new password for the user. This field is write-only.
    """
    password = serializers.CharField(write_only=True, required=True)

    def validate_password(self, value):
        """
        Validate the provided password against Django's password validation rules.

        Args:
            value (str): The password to validate.

        Raises:
            ValidationError: If the password is invalid, with a list of error messages.
        
        Returns:
            str: The validated password.
        """
        try:
            validate_password(value)
        except serializers.ValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})
        return value

    def create(self, user_id, validated_data):
        """
        Set a new password for the user identified by user_id.

        Args:
            user_id (int): The ID of the user for whom the password is being set.
            validated_data (dict): The validated data containing the new password.

        Raises:
            ValidationError: If the user with the specified ID does not exist.

        Returns:
            User: The updated user instance with the new password set.
        """
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError({"user_id": "User with this ID does not exist."})

        user.set_password(validated_data['password'])
        user.save()
        return user

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing an existing user's password.

    Attributes:
        new_password (str): The new password for the user. This field is write-only.
    """
    new_password = serializers.CharField(write_only=True, required=True)

    def validate_new_password(self, value):
        """
        Validate the provided new password against Django's password validation rules.

        Args:
            value (str): The new password to validate.

        Raises:
            ValidationError: If the new password is invalid, with a list of error messages.
        
        Returns:
            str: The validated new password.
        """
        try:
            validate_password(value)
        except serializers.ValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})
        return value

class SendEmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for sending an email verification request.

    Attributes:
        email (str): The email address of the user that requires verification.
    """
    email = serializers.EmailField(required=True)

class VerifyEmailCodeSerializer(serializers.Serializer):
    """
    Serializer for verifying the email verification code.

    Attributes:
        email (str): The email address of the user attempting to verify.
        verification_code (str): The verification code sent to the user's email.
    """
    email = serializers.EmailField(required=True)
    verification_code = serializers.CharField(required=True)

    def validate_email(self, value):
        """
        Validate the provided email address.

        Args:
            value (str): The email address to validate.

        Raises:
            ValidationError: If no user exists with the given email address.

        Returns:
            str: The validated email address.
        """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("کاربری با این ایمیل پیدا نشد.")
        return value

