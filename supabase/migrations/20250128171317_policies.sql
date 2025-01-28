--- -----------------------------------------
--- enable rls
--- -----------------------------------------
alter table public.user_profiles enable row level security;
alter table public.tenants enable row level security;
alter table public.tenant_members enable row level security;
alter table public.tenant_user_roles enable row level security;
alter table public.default_role_permissions enable row level security;

--- -----------------------------------------
--- user_profiles table policies
--- -----------------------------------------
create policy "Allow logged-in read access" on public.user_profiles for select using ( auth.role() = 'authenticated' );
create policy "Allow individual insert access" on public.user_profiles for insert with check ( auth.uid() = id );
create policy "Allow individual update access" on public.user_profiles for update using ( auth.uid() = id );
create policy "Allow system user management" on public.user_profiles for all using ( authorise('system.users.manage') );

--- -----------------------------------------
--- tenants table policies
--- -----------------------------------------
create policy "Allow authorised read access" on public.tenants for select using ( authorise('tenants.read') );
create policy "Allow authorised update access" on public.tenants for update using ( authorise('tenants.update') );
create policy "Allow authorised insert access" on public.tenants for insert with check ( authorise('tenants.create'::app_permission) );
create policy "Allow authorised delete access" on public.tenants for delete using ( authorise('tenants.delete') or authorise('system.all') );

-- Allow users to read tenants they're members of
create policy "Allow members to read tenant"
    on public.tenants
    for select using (
        exists (
            select 1 
            from public.tenant_members 
            where tenant_id = tenants.id 
            and user_id = auth.uid()
        )
    );

-- Allow users to read tenants they just created
create policy "Allow creator to read tenant"
    on public.tenants
    for select using (
        created_by = auth.uid()
    );

--- -----------------------------------------
--- tenant_members policies
--- -----------------------------------------
create policy "Allow tenant admins to manage members"
    on public.tenant_members
    for all using (
        authorise('tenants.members.assign', tenant_id)
    );

create policy "Allow members to view their own memberships"
    on public.tenant_members
    for select using (
        user_id = auth.uid()
    );

create policy "Allow authorised member viewing"
    on public.tenant_members
    for select using (
        authorise('tenants.members.view', tenant_id)
        or authorise('tenants.all', tenant_id)
    );

create policy "Allow authorised member removal"
    on public.tenant_members
    for delete using (
        authorise('tenants.members.remove', tenant_id)
    );

--- -----------------------------------------
--- tenant_user_roles policies
--- -----------------------------------------
create policy "Allow tenant admins to manage roles"
    on public.tenant_user_roles
    for all using (
        authorise('tenants.roles.assign', tenant_id)
    );

create policy "Allow users to view their own roles"
    on public.tenant_user_roles
    for select using (
        user_id = auth.uid()
    );

create policy "Allow role management by system admins"
    on public.tenant_user_roles
    for all using (
        authorise('system.roles.manage')
    );

create policy "Allow authorised role viewing"
    on public.tenant_user_roles
    for select using (
        authorise('tenants.roles.view', tenant_id)
        or authorise('tenants.all', tenant_id)
    );

create policy "Prevent self-role modification"
    on public.tenant_user_roles
    with check (
        user_id != auth.uid()
    );

--- -----------------------------------------
--- default_role_permissions policies
--- -----------------------------------------
-- Default roles should be readable by all authenticated users
create policy "Allow authenticated read access"
    on public.default_role_permissions
    for select using (
        auth.role() = 'authenticated'
    );

-- Only allow system admins to modify default roles
create policy "Allow system admins to manage"
    on public.default_role_permissions
    for all using (
        authorise('system.all')
    );