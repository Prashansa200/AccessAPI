from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Resource, Access
from django.contrib.auth import authenticate


# ---------------------------
# User Signup Serializer
# ---------------------------
class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("username", "email", "password", "first_name", "last_name")

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email", ""),
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", "")
        )
        return user


# ---------------------------
# Login Serializer
# ---------------------------
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        # Find the user by email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password")

        # Authenticate using username (since Django’s authenticate uses username)
        user = authenticate(username=user.username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid email or password")

        data["user"] = user
        return data


# ---------------------------
# Resource Serializer
# ---------------------------
# class ResourceSerializer(serializers.ModelSerializer):
#     owner = serializers.ReadOnlyField(source="owner.username")

#     class Meta:
#         model = Resource
#         fields = ("id", "name", "description", "owner", "created_at")

class ResourceSerializer(serializers.ModelSerializer):
    # show username in response + allow setting owner via username
    owner = serializers.SlugRelatedField(
        slug_field="username",
        queryset=User.objects.all()
    )

    class Meta:
        model = Resource
        fields = ("id", "name", "description", "owner", "created_at")
# ---------------------------
# Access Serializer
# ---------------------------
class AccessSerializer(serializers.ModelSerializer):
    user = serializers.SlugRelatedField(
        slug_field="username",
        queryset=User.objects.all()
    )
    resource = serializers.PrimaryKeyRelatedField(
        queryset=Resource.objects.all()
    )

    class Meta:
        model = Access
        fields = ("id", "resource", "user", "can_read", "can_edit")
        read_only_fields = ("id",)


# ---------------------------
# Transfer Ownership Serializer
# ---------------------------
class TransferOwnershipSerializer(serializers.Serializer):
    resource = serializers.PrimaryKeyRelatedField(
        queryset=Resource.objects.all(),
        help_text="Select a resource from dropdown"
    )
    new_owner = serializers.SlugRelatedField(
        queryset=User.objects.all(),
        slug_field="username",
        help_text="Select a new owner from dropdown"
    )
    keep_as_editor = serializers.BooleanField(
        default=True,
        help_text="Keep old owner as editor?"
    )

    def validate_resource(self, value):
        if not value:
            raise serializers.ValidationError("Resource is required")
        return value

    def validate_new_owner(self, value):
        if not value:
            raise serializers.ValidationError("New owner is required")
        return value
