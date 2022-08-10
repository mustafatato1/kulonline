from django.contrib import admin
from vendor.models import Vendor
from . models import User , UserProfile
from django.contrib.auth.admin import UserAdmin

# Register your models here.

class VendorAdmin(admin.ModelAdmin):
    list_display = ('user', 'vendor_name', 'is_approved', 'created_at')
    list_display_links = ('user', 'vendor_name')
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()



admin.site.register(Vendor, VendorAdmin)
# admin.site.register(UserProfile)