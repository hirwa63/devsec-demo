from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.http import url_has_allowed_host_and_scheme
from .models import UserProfile, LoginAttempt, AuditLog
from .utils import record_audit_log, get_client_ip

def get_safe_redirect_url(request, redirect_to, fallback_url):
    """
    Validate the redirect URL to prevent open redirect vulnerabilities.
    """
    if redirect_to and url_has_allowed_host_and_scheme(
        url=redirect_to,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect_to
    return fallback_url

def register(request):
    if request.user.is_authenticated:
        return redirect('profile')
    
    redirect_to = request.POST.get('next') or request.GET.get('next')

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            UserProfile.objects.create(user=user, role='viewer')
            
            # AUDIT LOG: Registration
            record_audit_log('registration', request, user=user, details="New user created")
            
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}! Please login.')
            
            safe_url = get_safe_redirect_url(request, redirect_to, 'login')
            return redirect(safe_url)
        else:
            messages.error(request, 'Registration failed. Please correct the errors.')
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form, 'next': redirect_to})

def login_view(request):
    """Login view with brute-force protection and safe redirect validation."""
    if request.user.is_authenticated:
        return redirect('profile')

    redirect_to = request.POST.get('next') or request.GET.get('next')
    max_attempts = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
    cooldown_minutes = getattr(settings, 'LOGIN_COOLDOWN_MINUTES', 15)

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        username = request.POST.get('username', '')
        ip_address = get_client_ip(request)

        # Check if this username is currently locked out
        recent_failures = LoginAttempt.get_recent_failures(username, cooldown_minutes)
        if recent_failures >= max_attempts:
            messages.error(
                request,
                f'This account is temporarily locked due to too many failed login attempts. '
                f'Please try again in {cooldown_minutes} minutes.'
            )
            return render(request, 'accounts/login.html', {
                'form': AuthenticationForm(),
                'is_locked': True,
                'cooldown_minutes': cooldown_minutes,
                'next': redirect_to,
            })

        if form.is_valid():
            user = authenticate(
                request,
                username=form.cleaned_data['username'],
                password=form.cleaned_data['password'],
            )
            if user is not None:
                login(request, user)
                # Clear failed attempts on successful login
                LoginAttempt.clear_attempts(username)
                
                # AUDIT LOG: Login Success
                record_audit_log('login_success', request, user=user)
                
                messages.success(request, f'Welcome back, {username}!')
                
                safe_url = get_safe_redirect_url(request, redirect_to, 'profile')
                return redirect(safe_url)

        # Authentication failed — record the attempt
        LoginAttempt.record_failure(username, ip_address)
        
        # AUDIT LOG: Login Failure
        record_audit_log('login_failure', request, username_attempted=username, details="Invalid credentials")
        
        remaining = max_attempts - LoginAttempt.get_recent_failures(username, cooldown_minutes)

        if remaining <= 0:
            messages.error(
                request,
                f'This account is now temporarily locked due to too many failed login attempts. '
                f'Please try again in {cooldown_minutes} minutes.'
            )
        elif remaining <= 2:
            messages.warning(
                request,
                f'Invalid username or password. {remaining} attempt(s) remaining before lockout.'
            )
        else:
            messages.error(request, 'Invalid username or password.')

    else:
        form = AuthenticationForm()

    return render(request, 'accounts/login.html', {'form': form, 'next': redirect_to})

def logout_view(request):
    if request.method == 'POST':
        user = request.user
        logout(request)
        
        # AUDIT LOG: Logout
        if user.is_authenticated:
            record_audit_log('logout', request, user=user)
            
        messages.success(request, 'You have been logged out.')
    return redirect('login')

@login_required
@ensure_csrf_cookie
def home(request):
    profile = UserProfile.objects.get(user=request.user)
    return render(request, 'accounts/dashboard.html', {'profile': profile})

@login_required
@ensure_csrf_cookie
def profile_view(request):
    """View current user's profile with recent security logs."""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    # Include recent audit logs for the user
    logs = AuditLog.objects.filter(user=request.user)[:10]
    return render(request, 'accounts/profile.html', {'profile': profile, 'logs': logs})

@login_required
def update_display_name(request):
    """Update the user's display name via AJAX."""
    if request.method == 'POST':
        display_name = request.POST.get('display_name', '')
        profile = request.user.userprofile
        profile.display_name = display_name
        profile.save()
        return JsonResponse({'status': 'success', 'display_name': display_name})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

def is_admin(user):
    return hasattr(user, 'userprofile') and user.userprofile.role == 'admin'

@login_required
@user_passes_test(is_admin)
def update_role(request, user_id):
    """Admin-only view to change user roles with audit logging."""
    from django.contrib.auth.models import User
    target_user = get_object_or_404(User, pk=user_id)
    target_profile, created = UserProfile.objects.get_or_create(user=target_user)
    
    if request.method == 'POST':
        old_role = target_profile.role
        new_role = request.POST.get('role')
        if new_role in [choice[0] for choice in UserProfile.ROLE_CHOICES]:
            target_profile.role = new_role
            target_profile.save()
            
            # AUDIT LOG: Privilege Change
            record_audit_log(
                'privilege_change', 
                request, 
                user=request.user, 
                details=f"Changed user {target_user.username} role: {old_role} -> {new_role}"
            )
            
            messages.success(request, f"Updated {target_user.username} to {new_role}")
    
    return redirect('profile')
