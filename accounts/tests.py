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
        for i in range(5):
            self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'WrongPassword!',
            })
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

    def test_registration_logs_event(self):
        """Verify that user registration is logged."""
        self.client.post(self.register_url, {
            'username': 'newaudituser',
            'password1': 'password123!',
            'password2': 'password123!',
        })
        new_user = User.objects.get(username='newaudituser')
        log = AuditLog.objects.filter(user=new_user, event_type='registration').first()
        self.assertIsNotNone(log)

    def test_privilege_change_logs_event(self):
        """Verify that admin-driven role changes are audited."""
        admin_user = User.objects.create_superuser(username='admin', password='adminpassword', email='admin@test.com')
        UserProfile.objects.get_or_create(user=admin_user, role='admin')
        
        other_user = User.objects.create_user(username='other', password='password')
        UserProfile.objects.get_or_create(user=other_user, role='viewer')
        
        self.client.login(username='admin', password='adminpassword')
        
        self.client.post(reverse('update_role', args=[other_user.id]), {
            'role': 'editor'
        })
        
        log = AuditLog.objects.filter(event_type='privilege_change').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, admin_user)
        self.assertIn('viewer -> editor', log.details)
