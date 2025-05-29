from typing import Dict, Any, Optional
import asyncio
from kinde_sdk.auth.permissions import Permissions as KindePermissions

class Permissions:
    def __init__(self):
        self.kinde_permissions = KindePermissions()

    async def get_permissions(self) -> Dict[str, Any]:
        """Get all permissions for the current user."""
        return await self.kinde_permissions.get_permissions()

    async def get_permission(self, permission_key: str) -> Optional[Dict[str, Any]]:
        """Get a specific permission for the current user."""
        return await self.kinde_permissions.get_permission(permission_key)
