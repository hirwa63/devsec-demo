from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages


def role_required(required_role):
    """
    Decorator to restrict views to users with specific roles.
    
    Args:
        required_role (str): The role required to access the view ('admin', 'editor', 'viewer')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Anonymous users
            if not request.user.is_authenticated:
                messages.error(request, 'You must be logged in to access this page.')
                return redirect('login')
            
            # Check if user has required role
            try:
                user_profile = request.user.userprofile
                if user_profile.role == required_role or user_profile.role == 'admin':
                    return view_func(request, *args, **kwargs)
            except:
                pass
            
            # Unauthorized access
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('home')
        
        return wrapper
    return decorator


def admin_required(view_func):
    """Restrict view to admin users only."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'You must be logged in to access this page.')
            return redirect('login')
        
        try:
            user_profile = request.user.userprofile
            if user_profile.role == 'admin':
                return view_func(request, *args, **kwargs)
        except:
            pass
        
        messages.error(request, 'Admin access required.')
        return redirect('home')
    
    return wrapper


def editor_required(view_func):
    """Restrict view to editor and admin users."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'You must be logged in to access this page.')
            return redirect('login')
        
        try:
            user_profile = request.user.userprofile
            if user_profile.role in ['editor', 'admin']:
                return view_func(request, *args, **kwargs)
        except:
            pass
        
        messages.error(request, 'Editor access required.')
        return redirect('home')
    
    return wrapper
