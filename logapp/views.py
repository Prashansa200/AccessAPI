from rest_framework import generics, status
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .models import Resource, Access
from .serializers import (
    UserSignupSerializer, LoginSerializer,
    ResourceSerializer, AccessSerializer, TransferOwnershipSerializer
)

# ----------------------------------------------------------------------
# 1️⃣ Signup View
# ----------------------------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSignupSerializer
    authentication_classes = []
    permission_classes = []


# ----------------------------------------------------------------------
# 2️⃣ Login View
# ----------------------------------------------------------------------


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = []
    permission_classes = []

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")
        if not email or not password:
            return Response({"detail": "Email and password are required."}, status=400)

        user = User.objects.filter(email=email).first()
        if not user or not user.check_password(password):
            return Response({"detail": "Invalid credentials."}, status=400)

        return Response({
            "message": "Login successful",
            "username": user.username,
            "email": user.email,
            "user_id": user.id
        }, status=200)

# ----------------------------------------------------------------------
# 3️⃣ Resource Create/List View
# ----------------------------------------------------------------------

from django.shortcuts import get_object_or_404
from rest_framework.exceptions import ValidationError
class ResourceListCreateView(generics.ListCreateAPIView):
    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer
    authentication_classes = []  # No token/session
    permission_classes = []      # Public for now

    def perform_create(self, serializer):
        username = self.request.data.get("owner")

        if not username:
            raise ValidationError({"owner": "This field is required."})

        user = get_object_or_404(User, username=username)
        serializer.save(owner=user)

# ----------------------------------------------------------------------
# 4️⃣ Resource Retrieve/Update/Delete View
# ----------------------------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class ResourceRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer
    authentication_classes = []
    permission_classes = []


# ----------------------------------------------------------------------
# 5️⃣ Grant / Revoke Access View
# ----------------------------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class GrantAccessView(generics.GenericAPIView):
    serializer_class = AccessSerializer
    authentication_classes = []
    permission_classes = []

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


# ----------------------------------------------------------------------
# 6️⃣ Transfer Ownership View
# ----------------------------------------------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class TransferOwnershipView(generics.GenericAPIView):
    serializer_class = TransferOwnershipSerializer
    authentication_classes = []
    permission_classes = []

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
