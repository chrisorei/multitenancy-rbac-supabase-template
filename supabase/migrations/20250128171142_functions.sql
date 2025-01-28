--- When a new user signs up to the application
create function public.handle_new_user()
returns trigger as $$
begin
    --- Create user profile
    insert into public.user_profiles (id)
    values (new.id);

    --- Assign basic role to user (system-wide)
    insert into public.tenant_user_roles (
        tenant_id,
        user_id,
        role,
        role_type
    )
    values (
        null,                              --- null tenant_id means system-wide role
        new.id,
        'basic_user',
        'default'                          --- using default role type since basic_user is a system role
    );

    return new;
end;
$$ language plpgsql security definer set search_path = public;

--- Trigger to handle new user registration
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

--- When a new tenant is created
create or replace function handle_new_tenant()
returns trigger as $$
begin
    -- Assign administrator role to current user in new tenant
    insert into public.tenant_user_roles (
        tenant_id,
        user_id,
        role_type,
        role
    )
    values (
        new.id, 
        auth.uid(), 
        'default', 
        'administrator'
    );

    -- Insert user into tenant members
    insert into public.tenant_members (
        tenant_id,
        user_id,
        created_at
    )
    values (
        new.id,
        auth.uid(),
        now()
    );

    return new;
end;
$$ language plpgsql security definer set search_path = public;

-- Trigger for new tenant creation
create trigger on_tenant_created
    after insert on public.tenants
    for each row execute function public.handle_new_tenant();