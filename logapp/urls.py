from django.urls import path
from .views import (
    SignupView, LoginView,
    ResourceListCreateView, ResourceRetrieveUpdateDestroyView,
    GrantAccessView, TransferOwnershipView
)

urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("resource/create/", ResourceListCreateView.as_view(), name="resource-create"),
    path("resources/<int:pk>/", ResourceRetrieveUpdateDestroyView.as_view(), name="resource-detail"),
    path("access/grant/", GrantAccessView.as_view(), name="grant-access"),
    path("access/transfer/", TransferOwnershipView.as_view(), name="transfer-ownership"),
]
