from rest_framework import generics, mixins, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import login as django_login, logout as django_logout
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from .models import Resource, Access
from .serializers import (
    UserSignupSerializer, LoginSerializer,
    ResourceSerializer, AccessSerializer,TransferOwnershipSerializer
)
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.db.models import Q


# 1) Signup - create user
class SignupView(generics.CreateAPIView):
    serializer_class = UserSignupSerializer
    queryset = User.objects.all()

# 2) Login - authenticate and create session (no token)
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = []  # allow unauthenticated to call login
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        django_login(request, user)  # sets session cookie
        return Response({"message": "Logged in", "user_id": user.id, "username": user.username})

# Logout view (optional)
class LogoutView(generics.GenericAPIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        django_logout(request)
        return Response({"message": "Logged out"})

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

@method_decorator(csrf_exempt, name='dispatch')
class ResourceCreateView(generics.CreateAPIView):
    serializer_class = ResourceSerializer
    permission_classes = []
    authentication_classes = []

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
@method_decorator(csrf_exempt, name='dispatch')
class ResourceUpdateView(generics.GenericAPIView):
    serializer_class = ResourceSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def has_edit_permission(self, user, resource):
        """Check if user is owner or has edit access."""
        if resource.owner == user:
            return True
        return Access.objects.filter(resource=resource, user=user, can_edit=True).exists()

    def put(self, request, pk, *args, **kwargs):
        resource = get_object_or_404(Resource, pk=pk)

        # Check if user has edit permission
        if not self.has_edit_permission(request.user, resource):
            return Response({"detail": "You do not have permission to edit this resource"}, status=403)

        serializer = self.get_serializer(resource, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            "message": "Resource updated successfully",
            "resource": serializer.data
        }, status=200)

# 4) Grant / Update Access - owner only
# ✅ Grant or revoke access
class GrantAccessView(generics.GenericAPIView):
    serializer_class = AccessSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def has_edit_permission(self, user, resource):
        """Check if the user is owner or has edit access."""
        if resource.owner == user:
            return True
        return Access.objects.filter(resource=resource, user=user, can_edit=True).exists()

    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        resource = get_object_or_404(Resource, id=data.get("resource"))

        if not self.has_edit_permission(request.user, resource):
            return Response({"detail": "You do not have permission to grant access"}, status=403)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)

        user_obj = serializer.validated_data["user"]
        can_read = serializer.validated_data.get("can_read", False)
        can_edit = serializer.validated_data.get("can_edit", False)

        if user_obj == resource.owner:
            return Response({"detail": "Cannot modify owner's access"}, status=400)

        Access.objects.update_or_create(
            resource=resource,
            user=user_obj,
            defaults={"can_read": can_read, "can_edit": can_edit}
        )

        return Response({"message": "Access granted or updated successfully"}, status=200)

    def delete(self, request, *args, **kwargs):
        resource_id = request.data.get("resource")
        username = request.data.get("user")
        resource = get_object_or_404(Resource, id=resource_id)
        user_obj = get_object_or_404(User, username=username)

        if not self.has_edit_permission(request.user, resource):
            return Response({"detail": "You do not have permission to revoke access"}, status=403)

        Access.objects.filter(resource=resource, user=user_obj).delete()
        return Response({"message": "Access revoked"}, status=200)


# ✅ Edit resource (for owner or can_edit user)
class ResourceUpdateView(generics.GenericAPIView):
    serializer_class = ResourceSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def has_read_permission(self, user, resource):
        """Allow owner or anyone with read/edit access."""
        if resource.owner == user:
            return True
        return Access.objects.filter(
            resource=resource, user=user
        ).filter(Q(can_read=True) | Q(can_edit=True)).exists()

    def has_edit_permission(self, user, resource):
        """Allow only owner or users with can_edit=True."""
        if resource.owner == user:
            return True
        return Access.objects.filter(
            resource=resource, user=user, can_edit=True
        ).exists()

    # ✅ Read (for owner or read/edit access users)
    def get(self, request, pk, *args, **kwargs):
        resource = get_object_or_404(Resource, pk=pk)

        if not self.has_read_permission(request.user, resource):
            return Response({"detail": "You do not have permission to view this resource"}, status=403)

        serializer = self.get_serializer(resource)
        return Response(serializer.data, status=200)

    # ✅ Update (only for owner or can_edit users)
    def put(self, request, pk, *args, **kwargs):
        resource = get_object_or_404(Resource, pk=pk)

        if not self.has_edit_permission(request.user, resource):
            return Response({"detail": "You do not have permission to edit this resource"}, status=403)

        serializer = self.get_serializer(resource, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            "message": "Resource updated successfully",
            "resource": serializer.data
        }, status=200)
# 5) Transfer Ownership - owner transfers entire ownership to another user

class TransferOwnershipView(generics.GenericAPIView):
    serializer_class = TransferOwnershipSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Already returns objects because of PrimaryKeyRelatedField and SlugRelatedField
        resource = serializer.validated_data['resource']
        new_owner = serializer.validated_data['new_owner']
        keep_as_editor = serializer.validated_data['keep_as_editor']

        # Check if current user is the owner
        if resource.owner != request.user:
            return Response(
                {"detail": "Only the current owner can transfer ownership."},
                status=status.HTTP_403_FORBIDDEN
            )

        old_owner = resource.owner

        # Transfer ownership
        resource.owner = new_owner
        resource.save()

        # Remove any existing access record for new owner
        Access.objects.filter(resource=resource, user=new_owner).delete()

        # Handle old owner's access
        if keep_as_editor:
            Access.objects.update_or_create(
                resource=resource,
                user=old_owner,
                defaults={"can_read": True, "can_edit": True}
            )
        else:
            Access.objects.filter(resource=resource, user=old_owner).delete()

        return Response({
            "message": "Ownership transferred successfully.",
            "resource_id": resource.id,
            "new_owner": new_owner.username,
            "old_owner_became_editor": keep_as_editor
        }, status=status.HTTP_200_OK)
