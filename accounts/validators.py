import os
from django.core.exceptions import ValidationError

def validate_max_file_size(value):
    """Limit file size to 5MB."""
    limit = 5 * 1024 * 1024
    if value.size > limit:
        raise ValidationError('File too large. Size should not exceed 5 MB.')

def validate_image_extension(value):
    """Allow only specific image extensions."""
    ext = os.path.splitext(value.name)[1]
    valid_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    if not ext.lower() in valid_extensions:
        raise ValidationError('Unsupported file extension. Only JPG, PNG, and GIF allowed.')

def validate_document_extension(value):
    """Allow only specific document extensions."""
    ext = os.path.splitext(value.name)[1]
    valid_extensions = ['.pdf', '.doc', '.docx', '.txt']
    if not ext.lower() in valid_extensions:
        raise ValidationError('Unsupported file extension. Only PDF, DOC, and TXT allowed.')
