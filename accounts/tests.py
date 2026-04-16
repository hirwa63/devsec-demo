from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User
from django.urls import reverse
from accounts.models import LoginAttempt, UserProfile

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
        UserProfile.objects.create(user=self.user, role='viewer')
        self.login_url = reverse('login')

    def test_successful_login(self):
        """Test that valid credentials allow login."""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'CorrectPass123!',
        })
        self.assertEqual(response.status_code, 302)
        # We redirected to profile in the merged view logic
        self.assertRedirects(response, reverse('profile'))

    def test_failed_login_records_attempt(self):
        """Test that a failed login attempt is recorded in the database."""
        self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'WrongPassword!',
        })
        self.assertEqual(LoginAttempt.objects.filter(username='testuser').count(), 1)

    def test_multiple_failed_attempts_recorded(self):
        """Test that multiple failures are all tracked."""
        for i in range(3):
            self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'WrongPassword!',
            })
        self.assertEqual(LoginAttempt.objects.filter(username='testuser').count(), 3)

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
        # Should NOT redirect (login blocked), should stay on login page
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'temporarily locked')

    def test_successful_login_clears_attempts(self):
        """Test that successful login clears all previous failed attempts."""
        # Record some failures
        for i in range(3):
            self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'WrongPassword!',
            })
        self.assertEqual(LoginAttempt.objects.filter(username='testuser').count(), 3)

        # Successful login
        self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'CorrectPass123!',
        })
        # Attempts should be cleared
        self.assertEqual(LoginAttempt.objects.filter(username='testuser').count(), 0)


class CSRFTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='csrfuser', password='password123')
        UserProfile.objects.create(user=self.user)
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
        
        # Verify database update
        self.user.userprofile.refresh_from_db()
        self.assertEqual(self.user.userprofile.display_name, 'New Name')
