from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LoginAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(db_index=True, max_length=150)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_type', models.CharField(choices=[('registration', 'User Registration'), ('login_success', 'Login Success'), ('login_failure', 'Login Failure'), ('logout', 'User Logout'), ('privilege_change', 'Privilege Change'), ('password_change', 'Password Change')], max_length=20)),
                ('username_attempted', models.CharField(blank=True, max_length=150)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('details', models.TextField(blank=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
    ]
