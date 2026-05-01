from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('home/', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register, name='register'),

    # Profile
    path('profile/', views.profile_view, name='profile'),
    path('profile/<int:user_id>/', views.profile_view_by_id, name='profile_by_id'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('profile/update_ajax/', views.update_display_name, name='update_display_name'),

    # Role management
    path('update_role/<int:user_id>/', views.update_role, name='update_role'),

    # Role-based panels
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('editor/panel/', views.editor_panel, name='editor_panel'),

    # Password reset (Django built-in, secure token-based)
    path('password_reset/',
         auth_views.PasswordResetView.as_view(
             template_name='accounts/password_reset_form.html',
             email_template_name='accounts/password_reset_email.html',
             success_url='/accounts/password_reset/done/',
         ),
         name='password_reset'),
    path('password_reset/done/',
         auth_views.PasswordResetDoneView.as_view(
             template_name='accounts/password_reset_done.html',
         ),
         name='password_reset_done'),
    path('reset/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(
             template_name='accounts/password_reset_confirm.html',
             success_url='/accounts/reset/done/',
         ),
         name='password_reset_confirm'),
    path('reset/done/',
         auth_views.PasswordResetCompleteView.as_view(
             template_name='accounts/password_reset_complete.html',
         ),
         name='password_reset_complete'),
]
