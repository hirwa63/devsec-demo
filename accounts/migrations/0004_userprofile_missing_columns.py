import accounts.models
import accounts.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_userprofile_add_missing_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='display_name',
            field=models.CharField(blank=True, default='', max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userprofile',
            name='bio',
            field=models.TextField(blank=True, default=''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userprofile',
            name='avatar',
            field=models.ImageField(blank=True, null=True, upload_to=accounts.models.avatar_upload_path, validators=[accounts.validators.validate_max_file_size, accounts.validators.validate_image_extension]),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='document',
            field=models.FileField(blank=True, null=True, upload_to=accounts.models.doc_upload_path, validators=[accounts.validators.validate_max_file_size, accounts.validators.validate_document_extension]),
        ),
    ]
