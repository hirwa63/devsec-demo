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
        self.assertRedirects(response, reverse('home'))

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

    def test_warning_shown_near_lockout(self):
        """Test that a warning message is shown when near the lockout threshold."""
        # Use 4 failures (1 remaining before lockout at 5)
        for i in range(4):
            self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'WrongPassword!',
            })
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'WrongPassword!',
        })
        # Should show lockout message
        self.assertContains(response, 'temporarily locked')

    def test_lockout_does_not_affect_other_users(self):
        """Test that locking out one user does not affect another user."""
        other_user = User.objects.create_user(
            username='otheruser',
            password='OtherPass123!'
        )
        UserProfile.objects.create(user=other_user, role='viewer')

        # Lock out testuser
        for i in range(5):
            self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'WrongPassword!',
            })

        # otheruser should still be able to log in
        response = self.client.post(self.login_url, {
            'username': 'otheruser',
            'password': 'OtherPass123!',
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))

    def test_login_page_loads(self):
        """Test that the login page loads successfully."""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Login')
