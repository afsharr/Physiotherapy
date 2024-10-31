from django.contrib import admin
from .models import User, UserProfile, AdminProfile

@admin.register(User)   
class UserAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': ('username', 'first_name', 'last_name', 'email', 'password')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        ('Important Dates', {
            'fields': ('last_login', 'date_joined'),
        }),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )
    list_display = ('id','username', 'email', 'first_name', 'last_name', 'is_staff', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('username',)

@admin.register(UserProfile) 
class UserProfileAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': ('user', 'national_id', 'gender', 'date_of_birth', 'address','thumbnail')
        }),
        ('Medical History', {
            'fields': ('medical_history', 'has_osteoporosis', 'has_stroke_history', 'has_multiple_sclerosis', 'is_info_self_reported', 'email_verified')
        }),
    )
    list_display = ('id','user', 'date_of_birth', 'gender', 'email_verified')
    search_fields = ('user__username', 'user__email', 'national_id')
    ordering = ('user',)

@admin.register(AdminProfile)
class AdminProfileAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': ('user', 'national_id', 'phone_number', 'role', 'address','thumbnail')
        }),
    )
    list_display = ('id', 'user', 'role', 'phone_number', 'get_groups')  # اضافه کردن فیلد گروه‌ها
    search_fields = ('user__username', 'user__email', 'phone_number')
    ordering = ('user',)

    def get_groups(self, obj):
        # دریافت گروه‌های کاربر
        groups = obj.user.groups.all()
        return ", ".join([group.name for group in groups]) if groups else "بدون گروه"

    get_groups.short_description = 'گروه‌ها'  # عنوان فیلد در پنل ادمین