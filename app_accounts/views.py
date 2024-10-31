from django.conf import settings
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import Permission, Group
from django.shortcuts import get_object_or_404
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .models import UserProfile, AdminProfile
from .utils import send_sms, generate_verification_code
from Physiotherapy.redis_utils import redis_client
from .serializers import (
    UserProfileThumbnailSerializer,
    AdminProfileThumbnailSerializer,
    SMSLoginSerializer,
    UpdateUserProfileSerializer,
    UserProfileSerializer,
    CreateAdminProfileSerializer,
    UpdateAdminProfileSerializer,
    CreatePasswordSerializer,
    ChangePasswordSerializer,
    PasswordLoginSerializer,
    SendEmailVerificationSerializer,
    VerifyEmailCodeSerializer,
    )

User = get_user_model()

class SendVerificationCodeView(APIView):
    """
    View for sending a verification code to a phone number via SMS.

    Methods:
        POST: Sends a verification code to the provided phone number.
    """

    def post(self, request):
        phone_number = request.data.get('phone_number')
        code = generate_verification_code()
        send_sms(phone_number, code)  # Implement SMS sending logic
        redis_client.setex(f"verification_code_{phone_number}", 120, code)
        return Response({"success": True, "message": "کد تأیید ارسال شد."}, status=status.HTTP_200_OK)

class BaseLoginView(APIView):
    """
    Base view for login functionality, providing token creation.

    Methods:
        create_tokens: Generates access and refresh tokens for authenticated users.
    """

    def create_tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return Response({
            "success": True,
            "token": str(refresh.access_token),
            "refresh_token": str(refresh),
            "message": "ورود موفقیت‌آمیز بود."
        })

def verify_code(identifier, verification_code):
    """
    Verifies the provided verification code against the stored code.

    Parameters:
        identifier (str): Unique identifier for the verification code (e.g., phone number).
        verification_code (str): Code to verify.

    Returns:
        bool: True if the verification code matches, False otherwise.
    """
    stored_code = redis_client.get(identifier)
    return stored_code and stored_code.decode() == verification_code

class SMSLoginView(BaseLoginView):
    """
    View for logging in users via SMS verification.

    Methods:
        POST: Validates the verification code and logs the user in.
    """

    def post(self, request):
        serializer = SMSLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            verification_code = serializer.validated_data['verification_code']
            phone_number = serializer.validated_data.get('phone_number')

            if user.is_staff:
                phone_number = phone_number or self.get_admin_phone_number(user)
                if phone_number and verify_code(f"verification_code_{phone_number}", verification_code):
                    return self.create_tokens(user)

            else:
                if verify_code(f"verification_code_{user.username}", verification_code):
                    return self.create_tokens(user)

            return Response({"success": False, "message": "کد تأیید نامعتبر است."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_admin_phone_number(self, user):
        """Gets the phone number from the AdminProfile if exists."""
        try:
            admin_profile = AdminProfile.objects.get(user=user)
            return admin_profile.phone_number
        except AdminProfile.DoesNotExist:
            return None

class PasswordLoginView(BaseLoginView):
    """
    View for logging in users via password.

    Methods:
        POST: Validates the user's credentials and logs them in.
    """

    def post(self, request):
        serializer = PasswordLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            return self.create_tokens(user)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CreateUserProfileView(APIView):
    """
    View for creating a user profile.

    Methods:
        POST: Creates a new user profile and activates the user.
    """
    
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request, user_id):
        if not request.user.is_superuser:
            return Response({"error": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "کاربر پیدا نشد."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserProfileSerializer(data=request.data)
        if serializer.is_valid():
            user_profile = serializer.save(user=user)

            # Activate user
            user.is_active = True
            user.save()

            return Response({"message": "پروفایل با موفقیت ایجاد شد.", "profile_id": user_profile.id}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateUserProfileView(APIView):
    """
    View for updating an existing user profile.

    Methods:
        PUT: Updates the specified user profile with provided data.
    """

    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        if request.user.id != user_id and not request.user.is_superuser:
            return Response({"error": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        user = User.objects.select_related('userprofile').filter(id=user_id).first()
        if not user or not user.userprofile:
            return Response({"error": "کاربر یا پروفایل پیدا نشد."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UpdateUserProfileSerializer(user.userprofile, data=request.data, partial=True)
        if serializer.is_valid():
            updated_profile = serializer.save()
            return Response({
                "message": "پروفایل با موفقیت به‌روزرسانی شد.",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CreateAdminProfileView(APIView):
    """
    View for creating an admin profile.

    Methods:
        POST: Creates a new admin profile.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        if not request.user.is_superuser:
            return Response({"error": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        serializer = CreateAdminProfileSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Activate user
            user.is_active = True
            user.save()

            return Response({
                "message": "پروفایل با موفقیت ایجاد شد.",
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "phone_number": user.adminprofile.phone_number,
                "role": user.adminprofile.role,
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateAdminProfileView(APIView):
    """
    View for updating an existing admin profile.

    Methods:
        PATCH: Updates the specified admin profile with provided data.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def patch(self, request, user_id):
        if request.user.id != user_id and not request.user.is_superuser:
            return Response({"error": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        user = User.objects.select_related('adminprofile').filter(id=user_id).first()
        if not user:
            return Response({"error": "کاربر پیدا نشد."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UpdateAdminProfileSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                "message": "پروفایل با موفقیت به‌روزرسانی شد.",
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "phone_number": user.adminprofile.phone_number,
                "role": user.adminprofile.role,
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileThumbnailUploadView(APIView):
    """
    View for uploading and deleting a user profile thumbnail.

    Methods:
        POST: Uploads a thumbnail image for the user profile.
        DELETE: Deletes the existing thumbnail image from the user profile.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        if request.user.id != user_id and not request.user.is_superuser:
            return Response({"error": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        user_profile = UserProfile.objects.get(user_id=user_id)
        serializer = UserProfileThumbnailSerializer(user_profile, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, user_id):
        try:
            user_profile = UserProfile.objects.get(user_id=user_id)
            user_profile.thumbnail.delete()  # Delete image from filesystem
            user_profile.thumbnail = None  # Set field to None
            user_profile.save()  # Save changes
            return Response({'message': 'Thumbnail deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)


class AdminProfileThumbnailUploadView(APIView):
    """
    View for uploading and deleting an admin profile thumbnail.

    Methods:
        POST: Uploads a thumbnail image for the specified admin profile.
        DELETE: Deletes the existing thumbnail image from the specified admin profile.
    """
    
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request, admin_id):
        """
        Uploads a thumbnail for the specified admin profile.

        Parameters:
            request (Request): The request object containing the thumbnail data.
            admin_id (int): The ID of the admin profile to update.

        Returns:
            Response: A success message and the updated thumbnail data if successful, 
                      or an error message if validation fails.
        """
        try:
            if request.user.id != admin_id and not request.user.is_superuser:
                return Response({"error": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

            admin_profile = AdminProfile.objects.get(user_id=admin_id)
        except AdminProfile.DoesNotExist:
            return Response({'error': 'Admin profile not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = AdminProfileThumbnailSerializer(admin_profile, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, admin_id):
        """
        Deletes the thumbnail for the specified admin profile.

        Parameters:
            request (Request): The request object.
            admin_id (int): The ID of the admin profile from which to delete the thumbnail.

        Returns:
            Response: A success message if the thumbnail was deleted, 
                      or an error message if the admin profile is not found.
        """
        try:
            admin_profile = AdminProfile.objects.get(user_id=admin_id)
            admin_profile.thumbnail.delete()  # Delete image from filesystem
            admin_profile.thumbnail = None  # Set field to None
            admin_profile.save()  # Save changes
            return Response({'message': 'Thumbnail deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except AdminProfile.DoesNotExist:
            return Response({'error': 'Admin profile not found.'}, status=status.HTTP_404_NOT_FOUND)

class UserProfileView(APIView):
    """
    API view to retrieve a user profile by user ID.

    Methods:
        GET: Retrieves the specified user profile if the requester has permission.
    """
    
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        """
        Retrieves the specified user profile.

        Parameters:
            request (Request): The request object.
            user_id (int): The ID of the user profile to retrieve.

        Returns:
            Response: The user profile data if found, 
                      or an error message if not found or permission is denied.
        """
        try:
            if request.user.id != user_id and not request.user.is_staff:
                return Response({"error": "You do not have permission to view this profile."}, status=status.HTTP_403_FORBIDDEN)

            user_profile = UserProfile.objects.select_related('user').get(user__id=user_id)
            response_data = {
                'username': user_profile.user.username,
                'first_name': user_profile.user.first_name,
                'last_name': user_profile.user.last_name,
                'date_joined': user_profile.user.date_joined,
                'is_active': user_profile.user.is_active,
                'gender': user_profile.gender,
                'date_of_birth': user_profile.date_of_birth,
                'national_id': user_profile.national_id,
                'has_osteoporosis': user_profile.has_osteoporosis,
                'address': user_profile.address,
                'medical_history': user_profile.medical_history,
                'has_stroke_history': user_profile.has_stroke_history,
                'has_multiple_sclerosis': user_profile.has_multiple_sclerosis,
                'is_info_self_reported': user_profile.is_info_self_reported,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({"error": "UserProfile not found."}, status=status.HTTP_404_NOT_FOUND)

class UserProfilesView(APIView):
    """
    API view to retrieve a list of all user profiles.

    Methods:
        GET: Retrieves a list of all user profiles if the requester has admin permission.
    """
    
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """
        Retrieves a list of all user profiles.

        Parameters:
            request (Request): The request object.

        Returns:
            Response: A list of user profiles with selected information.
        """
        user_profiles = UserProfile.objects.select_related('user').all()
        response_data = [
            {
                'username': user_profile.user.username,
                'first_name': user_profile.user.first_name,
                'last_name': user_profile.user.last_name,
                'date_joined': user_profile.user.date_joined,
                'is_active': user_profile.user.is_active,
                'gender': user_profile.gender,
                'date_of_birth': user_profile.date_of_birth,
            }
            for user_profile in user_profiles
        ]
        return Response(response_data, status=status.HTTP_200_OK)

class AdminProfileView(APIView):
    """
    API view to retrieve an admin profile by user ID.

    Methods:
        GET: Retrieves the specified admin profile if the requester has permission.
    """
    
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        """
        Retrieves the specified admin profile.

        Parameters:
            request (Request): The request object.
            user_id (int): The ID of the admin profile to retrieve.

        Returns:
            Response: The admin profile data if found, 
                      or an error message if not found or permission is denied.
        """
        try:
            # Check if the current user is a superuser or the requested user
            if request.user.id != user_id and not request.user.is_superuser:
                return Response({"error": "You do not have permission to view this profile."}, status=status.HTTP_403_FORBIDDEN)

            admin_profile = AdminProfile.objects.select_related('user').get(user__id=user_id)
            response_data = {
                'username': admin_profile.user.username,
                'first_name': admin_profile.user.first_name,
                'last_name': admin_profile.user.last_name,
                'date_joined': admin_profile.user.date_joined,
                'national_id': admin_profile.national_id,
                'address': admin_profile.address,
                'phone_number': admin_profile.phone_number,
                'role': admin_profile.role,
                'thumbnail': admin_profile.thumbnail.url if admin_profile.thumbnail else None,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except AdminProfile.DoesNotExist:
            return Response({"error": "AdminProfile not found."}, status=status.HTTP_404_NOT_FOUND)

class AdminProfilesView(APIView):
    """
    API view to retrieve a list of all admin profiles.

    Methods:
        GET: Retrieves a list of all admin profiles if the requester has admin permission.
    """
    
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """
        Retrieves a list of all admin profiles.

        Parameters:
            request (Request): The request object.

        Returns:
            Response: A list of admin profiles with selected information.
        """
        admin_profiles = AdminProfile.objects.select_related('user').all()
        response_data = [
            {
                'username': admin_profile.user.username,
                'first_name': admin_profile.user.first_name,
                'last_name': admin_profile.user.last_name,
                'date_joined': admin_profile.user.date_joined,
                'phone_number': admin_profile.phone_number,
                'role': admin_profile.role,
            }
            for admin_profile in admin_profiles
        ]
        return Response(response_data, status=status.HTTP_200_OK)

class PermissionsView(APIView):
    """
    API view to retrieve all permissions.

    Methods:
        GET: Retrieves a list of all permissions if the requester is a superuser.
    """
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """
        Retrieves all permissions.

        Parameters:
            request (Request): The request object.

        Returns:
            Response: A list of permissions if the user is a superuser,
                      or an error message if permission is denied.
        """
        if not request.user.is_superuser:
            return Response({"error": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        permissions = Permission.objects.all()
        return Response(permissions.values(), status=status.HTTP_200_OK)

class GroupsView(APIView):
    """
    API view to retrieve all groups.

    Methods:
        GET: Retrieves a list of all groups.
    """
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        """
        Retrieves all groups.

        Parameters:
            request (Request): The request object.

        Returns:
            Response: A list of groups.
        """
        groups = Group.objects.all()
        return Response(groups.values(), status=status.HTTP_200_OK)

class DeleteUserView(APIView):
    """
    API view to delete a user by user ID.

    Methods:
        DELETE: Deletes the specified user.
    """
    permission_classes = [IsAuthenticated, IsAdminUser]

    def delete(self, request, user_id):
        """
        Deletes a user.

        Parameters:
            request (Request): The request object.
            user_id (int): The ID of the user to delete.

        Returns:
            Response: A success message if the user was deleted,
                      or an error message if the user was not found.
        """
        user = get_object_or_404(User, id=user_id)
        user.delete()
        return Response({"success": True, "message": "کاربر با موفقیت حذف شد."}, status=status.HTTP_200_OK)

class ActivateUserView(APIView):
    """
    API view to activate a user by user ID.

    Methods:
        POST: Activates the specified user.
    """
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request, user_id):
        """
        Activates a user.

        Parameters:
            request (Request): The request object.
            user_id (int): The ID of the user to activate.

        Returns:
            Response: A success message if the user was activated,
                      or an error message if the user was not found.
        """
        target_user = get_object_or_404(User, id=user_id)
        target_user.is_active = True
        target_user.save()
        return Response({"success": True, "message": "کاربر با موفقیت فعال شد."}, status=status.HTTP_200_OK)

class DeactivateUserView(APIView):
    """
    API view to deactivate a user by user ID.

    Methods:
        POST: Deactivates the specified user.
    """
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request, user_id):
        """
        Deactivates a user.

        Parameters:
            request (Request): The request object.
            user_id (int): The ID of the user to deactivate.

        Returns:
            Response: A success message if the user was deactivated,
                      or an error message if the user was not found.
        """
        target_user = get_object_or_404(User, id=user_id)
        target_user.is_active = False
        target_user.save()
        return Response({"success": True, "message": "کاربر با موفقیت مسدود شد."}, status=status.HTTP_200_OK)

class CreatePasswordView(APIView):
    """
    API view to create a password for a user.

    Methods:
        POST: Creates a password for the specified user.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        """
        Creates a password for a user.

        Parameters:
            request (Request): The request object.
            user_id (int): The ID of the user for whom to create a password.

        Returns:
            Response: A success message if the password was created,
                      or an error message if validation fails.
        """
        if request.user.id != user_id and not request.user.is_superuser:
            return Response({"error": "You do not have permission to create a user."}, status=status.HTTP_403_FORBIDDEN)

        serializer = CreatePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.create(user_id, serializer.validated_data)  # Pass user_id to serializer
            return Response({"success": "Password created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):
    """
    API view to change a user's password.

    Methods:
        PUT: Changes the password for the specified user.
    """
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        """
        Changes a user's password.

        Parameters:
            request (Request): The request object.
            user_id (int): The ID of the user whose password to change.

        Returns:
            Response: A success message if the password was changed,
                      or an error message if validation fails or the user is not found.
        """
        if request.user.id != user_id and not request.user.is_superuser:
            return Response({"error": "You do not have permission to change this password."}, status=status.HTTP_403_FORBIDDEN)

        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(id=user_id)
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                return Response({"success": "Password changed successfully."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SendEmailVerificationCodeView(APIView):
    """
    API view to send an email verification code.

    Methods:
        POST: Sends a verification code to the user's email.
    """
    def post(self, request):
        """
        Sends an email verification code.

        Parameters:
            request (Request): The request object containing the user's email.

        Returns:
            Response: A success message if the email was sent,
                      or an error message if validation fails.
        """
        serializer = SendEmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = get_object_or_404(User, email=email)

            verification_code = generate_verification_code()
            redis_client.setex(f"verification_code_{email}", 120, verification_code)

            subject = 'تأیید ایمیل'
            html_message = render_to_string('email_verification.html', {'verification_code': verification_code})
            plain_message = strip_tags(html_message)

            email_message = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, [email])
            email_message.attach_alternative(html_message, "text/html")
            email_message.send()

            return Response({"success": True, "message": "کد تأیید به ایمیل شما ارسال شد."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailCodeView(APIView):
    """
    API view to verify the email verification code.

    Methods:
        POST: Verifies the code sent to the user's email.
    """
    def post(self, request):
        """
        Verifies the email verification code.

        Parameters:
            request (Request): The request object containing the email and verification code.

        Returns:
            Response: A success message if the code is valid,
                      or an error message if the code is invalid or expired.
        """
        serializer = VerifyEmailCodeSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            verification_code = serializer.validated_data['verification_code']

            user_profile = get_object_or_404(UserProfile, user__email=email)

            if verify_code(f"verification_code_{email}", verification_code):
                user_profile.email_verified = True
                user_profile.save()
                redis_client.delete(f"verification_code_{email}")
                return Response({"success": True, "message": "ایمیل با موفقیت تأیید شد."}, status=status.HTTP_200_OK)
            else:
                return Response({"success": False, "message": "کد تأیید نامعتبر است یا منقضی شده است."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
