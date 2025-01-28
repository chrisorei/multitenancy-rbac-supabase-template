--- Seed file for default role permissions
--- These roles are system-wide and can be assigned to users in any tenant

-- Add default role permissions
insert into public.default_role_permissions (
    role, permissions, notes
)
values 
    (
        'basic_user'::public.app_role, --- role
        array['tenants.create']::public.app_permission[], --- permissions
        'Basic user role assigned to all new users. Allows new tenant creation.' --- notes
    ),
    (
        'administrator'::public.app_role,
        array['tenants.all']::public.app_permission[],
        'Administrator role with full access to ALL tenants.'
    ),
    (
        'tenant_moderator'::public.app_role,
        array[
            'tenants.read',
            'tenants.update',
            'tenants.members.assign',
            'tenants.roles.edit',
            'tenants.roles.create',
            'tenants.roles.delete'
        ]::public.app_permission[],
        'Moderators can read tenants, invite, assign and remove tenant members, create and delete tenant roles'
    ),
    (
        'member'::public.app_role,
        array['tenants.read']::public.app_permission[],
        'Basic member with tenant read access and write access to tenant data. @dev: should be expanded to include other tenant actions based on application requirements.'
    );

--- System admin role (separate insert for clarity)
insert into public.default_role_permissions (
    role, permissions, notes
)
values 
    (
        'system_admin'::public.app_role,
        array['system.all']::public.app_permission[],
        'System admin role with full access to all system resources.'
    );