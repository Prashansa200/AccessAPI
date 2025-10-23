from django.db import models
from django.contrib.auth.models import User

class Resource(models.Model):
    # an example resource (could be a document, project etc.)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(User, related_name="owned_resources", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} (owner={self.owner.username})"

class Access(models.Model):
    # access entry: which user has what access on a resource
    resource = models.ForeignKey(Resource, related_name="access_entries", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="accesses", on_delete=models.CASCADE)
    can_read = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)
    # unique constraint so one row per user-resource
    class Meta:
        unique_together = ("resource", "user")

    def __str__(self):
        return f"{self.user.username} -> {self.resource.name} (R:{self.can_read} E:{self.can_edit})"
