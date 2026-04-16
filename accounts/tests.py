from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User
from django.urls import reverse
from accounts.models import LoginAttempt, UserProfile, AuditLog

@override_settings(MAX_LOGIN_ATTEMPTS=5, LOGIN_COOLDOWN_MINUTES=15)
class BruteForceProtectionTests(TestCase):
    """Test suite for brute-force login protection."""

    def setUp(self):
        """Set up test user."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='CorrectPass123!'
        )
        UserProfile.objects.get_or_create(user=self.user, role='viewer')
        self.login_url = reverse('login')

    def test_successful_login(self):
        """Test that valid credentials allow login."""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'CorrectPass123!',
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('profile'))

    def test_failed_login_records_attempt(self):
        """Test that a failed login attempt is recorded in the database."""
        self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'WrongPassword!',
        })
        self.assertEqual(LoginAttempt.objects.filter(username='testuser').count(), 1)

    def test_account_locked_after_max_attempts(self):
        """Test that account is locked after MAX_LOGIN_ATTEMPTS failures."""
        # Exhaust all attempts
        for i in range(5):
            self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'WrongPassword!',
            })

        # Next attempt should be blocked even with correct password
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'CorrectPass123!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'temporarily locked')


class CSRFTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='csrfuser', password='password123')
        UserProfile.objects.get_or_create(user=self.user)
        self.client = Client(enforce_csrf_checks=True)
        self.client.login(username='csrfuser', password='password123')
        self.url = reverse('update_display_name')

    def test_ajax_update_fails_without_csrf(self):
        """Verify that a POST request without a CSRF token fails with 403."""
        response = self.client.post(self.url, {'display_name': 'New Name'})
        self.assertEqual(response.status_code, 403)

    def test_ajax_update_succeeds_with_csrf(self):
        """Verify that a POST request with a CSRF token succeeds."""
        # Get a token first
        self.client.get(reverse('profile'))
        csrf_token = self.client.cookies['csrftoken'].value
        
        response = self.client.post(
            self.url, 
            {'display_name': 'New Name'},
            HTTP_X_CSRFTOKEN=csrf_token
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['display_name'], 'New Name')


class OpenRedirectTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='rediruser', password='password123')
        UserProfile.objects.get_or_create(user=self.user)
        self.login_url = reverse('login')
        self.register_url = reverse('register')

    def test_login_redirects_to_internal_url(self):
        """Verify that 'next=/accounts/profile/' redirects correctly."""
        response = self.client.post(self.login_url + '?next=/accounts/profile/', {
            'username': 'rediruser',
            'password': 'password123',
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/profile/', response.url)

    def test_login_blocks_external_redirect(self):
        """Verify that 'next=https://malicious.com' is rejected."""
        response = self.client.post(self.login_url + '?next=https://malicious.com', {
            'username': 'rediruser',
            'password': 'password123',
        })
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('malicious.com', response.url)
        self.assertIn('/accounts/profile/', response.url)


class AuditLogTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='audituser', password='password123')
        UserProfile.objects.get_or_create(user=self.user, role='viewer')
        self.login_url = reverse('login')
        self.register_url = reverse('register')

    def test_login_success_logs_event(self):
        """Verify that a successful login creates an AuditLog record."""
        self.client.post(self.login_url, {
            'username': 'audituser',
            'password': 'password123',
        })
        log = AuditLog.objects.filter(user=self.user, event_type='login_success').first()
        self.assertIsNotNone(log)

    def test_login_failure_logs_event(self):
        """Verify that a failed login attempt is recorded."""
        self.client.post(self.login_url, {
            'username': 'audituser',
            'password': 'wrongpassword',
        })
        log = AuditLog.objects.filter(username_attempted='audituser', event_type='login_failure').first()
        self.assertIsNotNone(log)


class XSSTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='xssuser', password='password123')
        UserProfile.objects.get_or_create(user=self.user)
        self.client.login(username='xssuser', password='password123')
        self.update_url = reverse('update_profile')
        self.profile_url = reverse('profile')

    def test_stored_xss_is_escaped(self):
        """Verify that a malicious script tag is escaped during rendering."""
        malicious_bio = "<script>alert('XSS')</script><b>Bold Text</b>"
        self.client.post(self.update_url, {'bio': malicious_bio})
        
        response = self.client.get(self.profile_url)
        content = response.content.decode()
        
        # It should show up as &lt;script&gt;
        self.assertIn("&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;", content)
