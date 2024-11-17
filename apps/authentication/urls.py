from django.urls import path
from apps.authentication import views


urlpatterns = [
    path('register/', views.RegisterInvestigator.as_view(), name='caf_register'),
    path('login/', views.LoginInvestigator.as_view(), name='caf_login'),
    path('logout/', views.logoutInvestigator, name='caf_logout'),
]