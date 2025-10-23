from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.views import APIView
from django.contrib.auth import login as django_login, logout as django_logout
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .models import Resource, Access
from .serializers import (
    UserSignupSerializer, LoginSerializer,
    ResourceSerializer, AccessSerializer, TransferOwnershipSerializer
)

# ------------------------------------------------
# 1. Signup View
# ------------------------------------------------
class SignupView(generics.CreateAPIView):
    serializer_class = UserSignupSerializer
    queryset = User.objects.all()


# ------------------------------------------------
# 2. Login View (Session-based)
# ------------------------------------------------
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = []  # allow unauthenticated users
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        django_login(request, user)  # creates session
        return Response({"message": "Logged in successfully", "username": user.username}, status=200)


# ------------------------------------------------
# 3. Logout View
# ------------------------------------------------
class LogoutView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        django_logout(request)
        return Response({"message": "Logged out successfully"}, status=200)


# ------------------------------------------------
# 4. Create Resource
# ------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class ResourceCreateView(generics.CreateAPIView):
    serializer_class = ResourceSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


# ------------------------------------------------
# 5. View / Update Resource (with permission checks)
# ------------------------------------------------
class ResourceUpdateView(generics.GenericAPIView):
    serializer_class = ResourceSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def has_read_permission(self, user, resource):
        if resource.owner == user:
            return True
        return Access.objects.filter(
            resource=resource, user=user
        ).filter(Q(can_read=True) | Q(can_edit=True)).exists()

    def has_edit_permission(self, user, resource):
        if resource.owner == user:
            return True
        return Access.objects.filter(resource=resource, user=user, can_edit=True).exists()

    def get(self, request, pk, *args, **kwargs):
        resource = get_object_or_404(Resource, pk=pk)
        if not self.has_read_permission(request.user, resource):
            return Response({"detail": "Permission denied to view"}, status=403)
        serializer = self.get_serializer(resource)
        return Response(serializer.data, status=200)

    def put(self, request, pk, *args, **kwargs):
        resource = get_object_or_404(Resource, pk=pk)
        if not self.has_edit_permission(request.user, resource):
            return Response({"detail": "Permission denied to edit"}, status=403)
        serializer = self.get_serializer(resource, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Resource updated", "resource": serializer.data}, status=200)


# ------------------------------------------------
# 6. Grant / Revoke Access
# ------------------------------------------------
class GrantAccessView(generics.GenericAPIView):
    serializer_class = AccessSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def has_edit_permission(self, user, resource):
        if resource.owner == user:
            return True
        return Access.objects.filter(resource=resource, user=user, can_edit=True).exists()

    def post(self, request, *args, **kwargs):
        data = request.data
        resource = get_object_or_404(Resource, id=data.get("resource"))
        if not self.has_edit_permission(request.user, resource):
            return Response({"detail": "You cannot grant access"}, status=403)

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

        return Response({"message": "Access granted/updated"}, status=200)

    def delete(self, request, *args, **kwargs):
        resource_id = request.data.get("resource")
        username = request.data.get("user")
        resource = get_object_or_404(Resource, id=resource_id)
        user_obj = get_object_or_404(User, username=username)

        if not self.has_edit_permission(request.user, resource):
            return Response({"detail": "You cannot revoke access"}, status=403)

        Access.objects.filter(resource=resource, user=user_obj).delete()
        return Response({"message": "Access revoked"}, status=200)


# ------------------------------------------------
# 7. Transfer Ownership
# ------------------------------------------------
class TransferOwnershipView(generics.GenericAPIView):
    serializer_class = TransferOwnershipSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        resource = serializer.validated_data["resource"]
        new_owner = serializer.validated_data["new_owner"]
        keep_as_editor = serializer.validated_data["keep_as_editor"]

        if resource.owner != request.user:
            return Response({"detail": "Only the owner can transfer ownership"}, status=403)

        old_owner = resource.owner
        resource.owner = new_owner
        resource.save()

        # Remove any old access for new owner
        Access.objects.filter(resource=resource, user=new_owner).delete()

        # Give old owner editor rights if requested
        if keep_as_editor:
            Access.objects.update_or_create(
                resource=resource,
                user=old_owner,
                defaults={"can_read": True, "can_edit": True}
            )
        else:
            Access.objects.filter(resource=resource, user=old_owner).delete()

        return Response({
            "message": "Ownership transferred",
            "resource_id": resource.id,
            "new_owner": new_owner.username,
            "old_owner_became_editor": keep_as_editor
        }, status=200)
