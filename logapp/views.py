from rest_framework import generics, status
from rest_framework.response import Response
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
@method_decorator(csrf_exempt, name='dispatch')
class SignupView(generics.CreateAPIView):
    serializer_class = UserSignupSerializer
    queryset = User.objects.all()
    permission_classes = []
    authentication_classes = []


# ------------------------------------------------
# 2. Login View (no session)
# ------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = []  # no session, no token
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        return Response({
            "message": "Login successful",
            "username": user.username,
            "user_id": user.id
        }, status=200)


# ------------------------------------------------
# 3. Logout View (no session)
# ------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        return Response({"message": "Logout successful"}, status=200)


# ------------------------------------------------
# 4. Create Resource
# ------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class ResourceCreateView(APIView):
    authentication_classes = []  # disable session/token auth
    permission_classes = []

    def post(self, request, *args, **kwargs):
        username = request.data.get("owner")
        if not username:
            return Response({"error": "Missing 'owner' field"}, status=400)

        user = User.objects.filter(username=username).first()
        if not user:
            return Response({"error": "User not found"}, status=404)

        serializer = ResourceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=user)
            return Response({"message": "Resource created", "data": serializer.data}, status=201)
        return Response(serializer.errors, status=400)


# ------------------------------------------------
# 5. View / Update Resource (with simple access checks)
# ------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class ResourceUpdateView(generics.GenericAPIView):
    serializer_class = ResourceSerializer
    permission_classes = []
    authentication_classes = []

    def get(self, request, pk, *args, **kwargs):
        resource = get_object_or_404(Resource, pk=pk)
        serializer = self.get_serializer(resource)
        return Response(serializer.data, status=200)

    def put(self, request, pk, *args, **kwargs):
        resource = get_object_or_404(Resource, pk=pk)
        serializer = self.get_serializer(resource, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "message": "Resource updated",
            "resource": serializer.data
        }, status=200)


# ------------------------------------------------
# 6. Grant / Revoke Access
# ------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class GrantAccessView(generics.GenericAPIView):
    serializer_class = AccessSerializer
    permission_classes = []
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        data = request.data
        resource = get_object_or_404(Resource, id=data.get("resource"))
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)

        user_obj = serializer.validated_data["user"]
        can_read = serializer.validated_data.get("can_read", False)
        can_edit = serializer.validated_data.get("can_edit", False)

        Access.objects.update_or_create(
            resource=resource,
            user=user_obj,
            defaults={"can_read": can_read, "can_edit": can_edit}
        )
        return Response({"message": "Access granted or updated"}, status=200)

    def delete(self, request, *args, **kwargs):
        resource_id = request.data.get("resource")
        username = request.data.get("user")
        resource = get_object_or_404(Resource, id=resource_id)
        user_obj = get_object_or_404(User, username=username)
        Access.objects.filter(resource=resource, user=user_obj).delete()
        return Response({"message": "Access revoked"}, status=200)


# ------------------------------------------------
# 7. Transfer Ownership
# ------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class TransferOwnershipView(generics.GenericAPIView):
    serializer_class = TransferOwnershipSerializer
    permission_classes = []
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        resource = serializer.validated_data["resource"]
        new_owner = serializer.validated_data["new_owner"]
        keep_as_editor = serializer.validated_data["keep_as_editor"]

        old_owner = resource.owner
        resource.owner = new_owner
        resource.save()

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
            "new_owner": new_owner.username
        }, status=200)
