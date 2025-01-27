from django.urls import path
from .views import (
    SendVerificationCodeView,
    SMSLoginView, 
    PasswordLoginView, 
    UserProfileView,
    UserProfilesView,
    AdminProfileView,
    AdminProfilesView,
    PermissionsView,
    GroupsView,
    CreateUserProfileView,
    CreatePasswordView,
    ChangePasswordView,
    DeleteUserView,
    ActivateUserView,
    DeactivateUserView, 
    UpdateUserProfileView,
    CreateAdminProfileView, 
    UpdateAdminProfileView, 
    UserProfileThumbnailUploadView, 
    AdminProfileThumbnailUploadView,
    SendEmailVerificationCodeView,
    VerifyEmailCodeView,
    )

urlpatterns = [
    path('send_verification_code/', SendVerificationCodeView.as_view(), name='send_verification_code'),
    path('login/sms/', SMSLoginView.as_view(), name='sms_login'),
    path('login/password/', PasswordLoginView.as_view(), name='password_login'),
    path('user-profiles/<int:user_id>/', UserProfileView.as_view(), name='user_profile'),
    path('user-profiles/', UserProfilesView.as_view(), name='user_profiles'),
    path('admin-profiles/<int:user_id>/', AdminProfileView.as_view(), name='admin_profile'),
    path('admin-profiles/', AdminProfilesView.as_view(), name='admin_profiles'),
    path('permissions/', PermissionsView.as_view(), name='permissions'),
    path('groups/', GroupsView.as_view(), name='groups'),
    path('users/<int:user_id>/create-password/', CreatePasswordView.as_view(), name='create_password'),
    path('users/<int:user_id>/change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('users/delete/<int:user_id>/', DeleteUserView.as_view(), name='delete_user'),
    path('users/activate/<int:user_id>/', ActivateUserView.as_view(), name='activate_user'),
    path('users/deactivate/<int:user_id>/', DeactivateUserView.as_view(), name='deactivate_user'),
    path('userprofile/create/<int:user_id>/', CreateUserProfileView.as_view(), name='create_user_profile'),
    path('userprofile/update/<int:user_id>/', UpdateUserProfileView.as_view(), name='update_user_profile'),
    path('admin/create/', CreateAdminProfileView.as_view(), name='create_admin_profile'),
    path('admin/update/<int:user_id>/', UpdateAdminProfileView.as_view(), name='update_admin_profile'),
    path('user_profiles/<int:user_id>/thumbnail/', UserProfileThumbnailUploadView.as_view(), name='user_profile_thumbnail_upload'),
    path('admin_profiles/<int:admin_id>/thumbnail/', AdminProfileThumbnailUploadView.as_view(), name='admin_profile_thumbnail_upload'),
    path('send-verification-code/', SendEmailVerificationCodeView.as_view(), name='send_verification_code'),
    path('verify-email-code/', VerifyEmailCodeView.as_view(), name='verify_email_code'),
]
