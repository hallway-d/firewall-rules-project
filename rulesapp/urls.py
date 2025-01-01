from django.urls import path
from . import views

urlpatterns = [
    path('generate-rules/', views.generate_rules_view, name='generate_rules'),
]

