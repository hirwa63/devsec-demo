from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register, name='register'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('profile/update_ajax/', views.update_display_name, name='update_display_name'),
    path('profile/upload/', views.upload_files, name='upload_files'),
    path('update_role/<int:user_id>/', views.update_role, name='update_role'),
]