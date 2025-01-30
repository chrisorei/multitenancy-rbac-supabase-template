create schema if not exists audit;

create type audit.log_type as enum (
    -- Tenant related events
    'tenant.created',
    'tenant.updated',
    'tenant.deleted',
    'tenant.member_added',
    'tenant.member_removed',
    'tenant.role_assigned',
    'tenant.role_removed',
    'tenant.invite_sent',
    'tenant.invite_accepted',
    'tenant.invite_revoked',

    -- Role/Permission events
    'role.created',
    'role.updated',
    'role.deleted',
    'permission.created',
    'permission.updated',
    'permission.deleted',

    -- User related events
    'user.created',
    'user.updated',
    'user.deleted',
    'user.login',
    'user.logout',
    'user.role_assigned',
    'user.role_removed'
);

comment on type audit.log_type is 'Enumeration of all available audit log types';

-- Main audit logs table
create table audit.logs (
    id uuid primary key default gen_random_uuid(),
    log_timestamp timestamptz not null default now(),
    log_type audit.log_type not null,
    tenant_id uuid references public.tenants(id),
    actor_id uuid references auth.users(id),
    actor_role public.app_role not null,
    actor_ip inet,
    description text not null,
    metadata jsonb,
    created_at timestamptz not null default now()
);

comment on table audit.logs is 'Table to store audit logs for all system events';
comment on column audit.logs.actor_id is 'The ID of the user who performed the action';
comment on column audit.logs.actor_role is 'The role of the user who performed the action';
comment on column audit.logs.metadata is 'Additional metadata about the event';

-- Index for efficient querying
create index idx_audit_logs_log_type on audit.logs (log_type);
create index idx_audit_logs_log_timestamp on audit.logs (log_timestamp);
create index idx_audit_logs_tenant_id on audit.logs (tenant_id);
create index idx_audit_logs_actor_id on audit.logs (actor_id);

-- -----------------------------------------
-- Helper functions
-- -----------------------------------------

-- Helper function to log events
create or replace function audit.log(
    log_type audit.log_type,
    description text,
    tenant_id uuid,
    metadata jsonb default '{}'::jsonb
)
returns uuid as $$
declare
    actor_id uuid;
    actor_role public.app_role;
    log_id uuid;
begin
    -- Get the current user
    actor_id := auth.uid();

    -- Get user's role only if we have an actor_id
    if actor_id is not null then
        select role into actor_role
        from public.tenant_user_roles tur
        where tur.user_id = actor_id
        and (tur.tenant_id is null or tur.tenant_id = log.tenant_id)
        order by tur.tenant_id nulls last
        limit 1;
    end if;

    -- Insert the log into the audit.logs table
    insert into audit.logs (
        log_type,
        description,
        tenant_id,
        actor_id,
        actor_role,
        metadata
    )
    values (
        log_type, 
        description, 
        tenant_id, 
        actor_id, 
        actor_role, 
        metadata
    )
    returning id into log_id;

    return log_id;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

comment on function audit.log is 'Helper function to create audit log entries with current user context';

-- Function to get audit logs with pagination and filtering
create or replace function audit.get_logs(
    p_tenant_id bigint default null,
    p_log_type audit.log_type default null,
    p_from_date timestamptz default null,
    p_to_date timestamptz default null,
    p_actor_id uuid default null,
    p_limit int default 50,
    p_offset int default 0
)
returns table (
    id uuid,
    log_timestamp timestamptz,
    log_type audit.log_type,
    tenant_id bigint,
    actor_id uuid,
    actor_role app_role,
    description text,
    metadata jsonb,
    actor_name text -- joins with user_profiles
) as $$
begin
    return query
    select 
        l.id,
        l.log_timestamp,
        l.log_type,
        l.tenant_id,
        l.actor_id,
        l.actor_role,
        l.description,
        l.metadata,
        up.display_name as actor_name
    from audit.logs l
    left join user_profiles up on l.actor_id = up.id
    where
        (p_tenant_id is null or l.tenant_id = p_tenant_id)
        and (p_log_type is null or l.log_type = p_log_type)
        and (p_from_date is null or l.log_timestamp >= p_from_date)
        and (p_to_date is null or l.log_timestamp <= p_to_date)
        and (p_actor_id is null or l.actor_id = p_actor_id)
    order by l.log_timestamp desc
    limit p_limit
    offset p_offset;
end;
$$ language plpgsql security invoker set search_path = public, audit, auth;

comment on function audit.get_logs is 'Function to retrieve audit logs with filtering and pagination';

-- -----------------------------------------
-- User related functions and triggers
-- -----------------------------------------

-- New user signup audit log and trigger
create or replace function audit.log_user_signup()
returns trigger as $$
begin
    perform audit.log(
        'user.created', 
        format('New user signed up: %s', new.email), 
        null, 
        jsonb_build_object(
            'email', new.email,
            'user_id', new.id,
            'created_at', new.created_at,
            'notes', 'New user signed up. Assigned basic_user role so user can create tenants.'
        )
    );
    return new;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger to log new user signup
create or replace trigger audit.on_user_signup
after insert on auth.users
for each row execute function audit.log_user_signup();

-- Email verified audit log and trigger
create or replace function audit.log_email_verified()
returns trigger as $$
begin
    -- Only trigger when email_confirmed_at is being set (null -> timestamp)
    if old.email_confirmed_at is null and new.email_confirmed_at is not null then
        perform audit.log(
            'user.email_verified', 
            format('Email verified for user: %s', new.email), 
            null, 
            jsonb_build_object(
                'email', new.email,
                'user_id', new.id,
                'email_confirmed_at', new.email_confirmed_at
            )
        );
    end if;
    return new;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger to log email verified
create or replace trigger audit.on_email_verified
after update on auth.users
for each row execute function audit.log_email_verified();

-- User had role assigned audit log and trigger
create or replace function audit.log_user_role_assigned()
returns trigger as $$
begin
    perform audit.log(
        'user.role_assigned', 
        format('User %s assigned role: %s', new.email, new.role), 
        null, 
        jsonb_build_object(
            'email', new.email,
            'role', new.role,
            'tenant_id', new.tenant_id
        )
    );
    return new;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger to log user role assigned
create or replace trigger audit.on_user_role_assigned
after update on public.tenant_user_roles
for each row execute function audit.log_user_role_assigned();

-- User had role removed audit log and trigger
create or replace function audit.log_user_role_removed()
returns trigger as $$
begin
    perform audit.log(
        'user.role_removed', 
        format('User %s removed from role: %s', old.email, old.role), 
        null, 
        jsonb_build_object(
            'email', old.email, 
            'role', old.role,
            'tenant_id', old.tenant_id
        )
    );
    return old;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger to log user role removed
create or replace trigger audit.on_user_role_removed
after delete on public.tenant_user_roles
for each row execute function audit.log_user_role_removed();

-- -----------------------------------------
-- Tenant related functions and triggers
-- -----------------------------------------

-- All tenant CRUD changes audit log and trigger
create or replace function audit.record_tenant_changes()
returns trigger as $$
declare
    change_type audit.log_type;
    description text;
    meta jsonb;
begin
    if (TG_OP = 'INSERT') then
        change_type := 'tenant.created';
        description := format('Tenant "%s" created', new.name);
        meta := jsonb_build_object(
            'tenant_name', new.name,
            'display_name', new.display_name
        );
    elsif (TG_OP = 'UPDATE') then
        change_type := 'tenant.updated';
        description := format('Tenant "%s" updated', new.name);
        meta := jsonb_build_object(
            'old_values', jsonb_build_object(
                'name', old.name,
                'display_name', old.display_name
            ),
            'new_values', jsonb_build_object(
                'name', new.name,
                'display_name', new.display_name
            )
        );
    elsif (TG_OP = 'DELETE') then
        change_type := 'tenant.deleted';
        description := format('Tenant "%s" deleted', old.name);
        meta := jsonb_build_object(
            'tenant_name', old.name,
            'display_name', old.display_name
        );
    end if;

    perform audit.log(
        change_type,
        description,
        case when TG_OP = 'DELETE' then old.id else new.id end,
        meta
    );

    if (TG_OP = 'DELETE') then
        return old;
    end if;
    return new;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger to log all tenant changes
create or replace trigger audit.on_tenant_changes
after insert or update or delete on public.tenants
for each row execute function audit.record_tenant_changes();

-- -----------------------------------------
-- All tenant members related functions and triggers
-- -----------------------------------------

-- Tenant member audit trigger
create or replace function audit.record_tenant_member_changes()
returns trigger as $$
declare
    change_type audit.log_type;
    description text;
    meta jsonb;
begin
    if (TG_OP = 'INSERT') then
        change_type := 'tenant.member_added';
        description := format('User %s added to tenant', new.user_id);
        meta := jsonb_build_object(
            'user_id', new.user_id,
            'tenant_id', new.tenant_id
        );
    elsif (TG_OP = 'DELETE') then
        change_type := 'tenant.member_removed';
        description := format('User %s removed from tenant', old.user_id);
        meta := jsonb_build_object(
            'user_id', old.user_id,
            'tenant_id', old.tenant_id
        );
    end if;

    perform audit.log(
        change_type,
        description,
        case when TG_OP = 'DELETE' then old.tenant_id else new.tenant_id end,
        meta
    );

    if (TG_OP = 'DELETE') then
        return old;
    end if;
    return new;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger to log all tenant member changes
create or replace trigger audit.on_tenant_member_changes
after insert or delete on public.tenant_members
for each row execute function audit.record_tenant_member_changes();

-- Role assignment/removal audit log and trigger
create or replace function audit.record_role_changes()
returns trigger as $$
declare
    change_type audit.log_type;
    description text;
    meta jsonb;
begin
    if (TG_OP = 'INSERT') then
        change_type := 'tenant.role_assigned';
        description := format('Role %s assigned to user %s', new.role, new.user_id);
        meta := jsonb_build_object(
            'user_id', new.user_id,
            'tenant_id', new.tenant_id,
            'role', new.role,
            'role_type', new.role_type
        );
    elsif (TG_OP = 'DELETE') then
        change_type := 'tenant.role_removed';
        description := format('Role %s removed from user %s', old.role, old.user_id);
        meta := jsonb_build_object(
            'user_id', old.user_id,
            'tenant_id', old.tenant_id,
            'role', old.role,
            'role_type', old.role_type
        );
    end if;

    perform audit.log(
        change_type,
        description,
        case when TG_OP = 'DELETE' then old.tenant_id else new.tenant_id end,
        meta
    );

    if (TG_OP = 'DELETE') then
        return old;
    end if;
    return new;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger to log role changes
create or replace trigger audit.on_role_changes
after insert or delete on public.tenant_user_roles
for each row execute function audit.record_role_changes();

-- -----------------------------------------
-- Authentication Events
-- -----------------------------------------

-- Function to log user authentication events
create or replace function audit.log_auth_event()
returns trigger as $$
declare
    change_type audit.log_type;
    description text;
    meta jsonb;
begin
    -- For sign in events
    if (TG_OP = 'INSERT') then
        change_type := 'user.login';
        description := format('User %s logged in', new.email);
        meta := jsonb_build_object(
            'email', new.email,
            'provider', new.provider,
            'ip_address', new.ip_address
        );
    -- For sign out events
    elsif (TG_OP = 'DELETE') then
        change_type := 'user.logout';
        description := format('User %s logged out', old.email);
        meta := jsonb_build_object(
            'email', old.email,
            'provider', old.provider
        );
    end if;

    perform audit.log(
        change_type,
        description,
        null, -- system-level event
        meta
    );

    if (TG_OP = 'DELETE') then
        return old;
    end if;
    return new;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger for auth events
create or replace trigger audit.on_auth_event
after insert or delete on auth.sessions
for each row execute function audit.log_auth_event();

-- -----------------------------------------
-- RLS and permissions
-- -----------------------------------------

alter table audit.logs enable row level security;

-- Policy to allow tenant admins or moderators to view audit logs
create policy "Allow tenant admins to view audit logs"
    on audit.logs
    for select
    using (
       tenant_id is null -- System level logs
       or exists (
            select 1
            from public.tenant_user_roles
            where user_id = auth.uid()
            and tenant_id = audit.logs.tenant_id
            and (
                public.authorise(
                    'tenants.audit.view',
                    tenant_id
                ) or
                public.authorise(
                    'tenants.all',
                    tenant_id
                )
            )
       )
    )

-- Grant necessary permissions
grant usage on schema audit to authenticated, service_role;
grant select on all tables in schema audit to authenticated, service_role;
grant execute on function audit.get_logs to authenticated, service_role;

-- Revoke necessary permissions
revoke execute on function audit.log from anon;
revoke execute on function audit.log from public;
revoke execute on function audit.log from authenticated;

-- Postgres role
alter default privileges for role postgres in schema audit grant all on tables to authenticated, service_role;
alter default privileges for role postgres in schema audit grant all on functions to authenticated, service_role;
alter default privileges for role postgres in schema audit grant all on routines to authenticated, service_role;
alter default privileges for role postgres in schema audit grant all on sequences to authenticated, service_role;

-- -----------------------------------------
-- Role Management Events
-- -----------------------------------------

-- Function to log role management events
create or replace function audit.record_role_definition_changes()
returns trigger as $$
declare
    change_type audit.log_type;
    description text;
    meta jsonb;
begin
    if (TG_OP = 'INSERT') then
        change_type := 'role.created';
        description := format('New role created: %s', new.role);
        meta := jsonb_build_object(
            'role', new.role,
            'permissions', new.permissions,
            'description', new.description,
            'role_type', new.role_type
        );
    elsif (TG_OP = 'UPDATE') then
        change_type := 'role.updated';
        description := format('Role updated: %s', new.role);
        meta := jsonb_build_object(
            'role', new.role,
            'old_permissions', old.permissions,
            'new_permissions', new.permissions,
            'old_description', old.description,
            'new_description', new.description,
            'role_type', new.role_type
        );
    elsif (TG_OP = 'DELETE') then
        change_type := 'role.deleted';
        description := format('Role deleted: %s', old.role);
        meta := jsonb_build_object(
            'role', old.role,
            'permissions', old.permissions,
            'description', old.description,
            'role_type', old.role_type
        );
    end if;

    perform audit.log(
        change_type,
        description,
        null, -- system-level event
        meta
    );

    if (TG_OP = 'DELETE') then
        return old;
    end if;
    return new;
end;
$$ language plpgsql security definer set search_path = public, audit, auth;

-- Trigger for role definition changes
create or replace trigger audit.on_role_definition_changes
after insert or update or delete on public.roles
for each row execute function audit.record_role_definition_changes();