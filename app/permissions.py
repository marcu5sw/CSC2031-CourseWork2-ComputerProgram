from flask_login import current_user
from flask_principal import Permission, RoleNeed, identity_loaded


#Defining permissions for the 3 pages
admin_permission = Permission(RoleNeed('admin'))
moderator_permission = Permission(RoleNeed('moderator'))
user_permission = Permission(RoleNeed('user'))


#Storing the current users role
def register_identity_permissions(app):
    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        if hasattr(current_user, 'role'):
            identity.provides.add(RoleNeed(current_user.role))
