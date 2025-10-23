from django.urls import path
from .views import (
    SignupView, LoginView, LogoutView,
    ResourceCreateView, GrantAccessView, TransferOwnershipView,ResourceUpdateView
)

urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("resource/create/", ResourceCreateView.as_view(), name="resource-create"),
    path("access/grant/", GrantAccessView.as_view(), name="access-grant"),
    path('resources/<int:pk>/', ResourceUpdateView.as_view(), name='update-resource'),
    path("access/transfer/", TransferOwnershipView.as_view(), name="transfer-ownership"),
]
