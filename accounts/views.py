from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from .models import UserProfile, LoginAttempt

def get_client_ip(request):
    """Extract the client IP address from the request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')

def register(request):
    if request.user.is_authenticated:
        return redirect('profile')
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            UserProfile.objects.create(user=user, role='viewer')
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}! Please login.')
            return redirect('login')
        else:
            messages.error(request, 'Registration failed. Please correct the errors.')
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})

def login_view(request):
    """Login view with brute-force protection."""
    if request.user.is_authenticated:
        return redirect('profile')

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
                messages.success(request, f'Welcome back, {username}!')
                return redirect('profile')

        # Authentication failed — record the attempt
        LoginAttempt.record_failure(username, ip_address)
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

    return render(request, 'accounts/login.html', {'form': form})

def logout_view(request):
    if request.method == 'POST':
        logout(request)
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
    """View current user's profile."""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    return render(request, 'accounts/profile.html', {'profile': profile})

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
