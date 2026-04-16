from django.urls import path, include
from django.contrib import admin
<<<<<<< HEAD
<<<<<<< HEAD
from django.urls import path, include
=======
>>>>>>> assignment/fix-open-redirects
=======
>>>>>>> assignment/add-auth-audit-logging
from django.views.generic import RedirectView

urlpatterns = [
    path('', RedirectView.as_view(url='accounts/login/', permanent=False)),
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
]
