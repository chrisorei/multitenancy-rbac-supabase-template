# Supabase Multi-Tenant RBAC Template

A production-ready template for implementing Multi-Tenancy and Role-Based Access Control (RBAC) using Supabase.

## Overview

This template provides a robust foundation for building multi-tenant applications with comprehensive role-based access control. It's designed to be minimal yet production-ready, allowing developers to extend it based on their specific needs.

### Features

- 🏢 **Multi-Tenancy**: Full isolation between different tenants
- 🔐 **Role-Based Access Control**: Flexible permission system
- 🔑 **Row Level Security**: Secure data access patterns
- 🌍 **System-wide and Tenant-specific Roles**: Granular access control
- 📝 **Comprehensive Audit Logging**: Track all system events
- ⚡ **Ready-to-use**: Just clone and deploy

## Architecture

### Multi-Tenancy Implementation

The system implements multi-tenancy through:

1. **Tenant Isolation**: Each tenant has its own isolated space
2. **Member Management**: Users can belong to multiple tenants
3. **Role Assignment**: Both system-wide and tenant-specific roles

### RBAC Structure

The RBAC system consists of:

#### 1. Permissions
Granular actions users can perform:
- **System-level**
  - `system.all`: Full system access
  - `system.users.manage`: Manage system users
  - `system.roles.manage`: Manage system roles
- **Tenant-level**
  - `tenants.create`: Create new tenants
  - `tenants.read`: View tenant details
  - `tenants.update`: Update tenant settings
  - `tenants.delete`: Remove tenants
  - `tenants.members.assign`: Manage tenant members
  - `tenants.roles.edit`: Modify tenant roles

#### 2. Roles
Collections of permissions:
- **System Roles**
  - `system_admin`: Full system access
  - `basic_user`: Can create tenants
- **Tenant Roles**
  - `administrator`: Full tenant access
  - `member`: Basic tenant access

#### 3. Role Assignment
Managed through the `tenant_user_roles` table:
- System-wide roles (null tenant_id)
- Tenant-specific roles

### Audit Logging System

The system includes a comprehensive audit logging mechanism that tracks all important events:

#### Event Types
- **User Events**
  - User creation, updates, and deletion
  - Authentication events (login/logout)
  - Role assignments and removals
- **Tenant Events**
  - Tenant creation, updates, and deletion
  - Member additions and removals
  - Role assignments within tenants
- **Role Management**
  - Role creation and deletion
  - Role permission updates
  - System and tenant-level role changes

#### Audit Log Features
- **Secure Logging**: Only the system can write logs
- **Rich Metadata**: Each log entry includes:
  - Timestamp
  - Event type
  - Actor (user who performed the action)
  - Tenant context (if applicable)
  - Detailed event description
  - Additional metadata
- **Access Control**: Logs are accessible based on user permissions
- **Querying**: Supports filtering by date, event type, tenant, and actor

## Getting Started

### Prerequisites

- [Supabase CLI](https://supabase.com/docs/guides/cli)
- Node.js 18+ (for example implementation)

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/supabase-multi-tenant-rbac
   cd supabase-multi-tenant-rbac
   ```

2. **Start Supabase locally**
   ```bash
   supabase start
   ```

3. **Apply migrations**
   ```bash
   supabase migration up
   ```

4. **Seed the database**
   ```bash
   supabase db reset
   ```

### Development Workflow

The recommended workflow using Supabase CLI:

1. **Create new migrations**
   ```bash
   supabase migration new your_migration_name
   ```

2. **Test locally**
   ```bash
   supabase db reset
   ```

3. **Push to production**
   ```bash
   supabase db push
   ```

## Framework Integration

### Next.js (App Router)

```typescript
// utils/supabase.ts
import { createClient } from '@supabase/supabase-js'

export const createServerClient = () => {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
}

// Example: Check permissions
async function hasPermission(permission: string, tenantId?: number) {
  const supabase = createServerClient()
  
  const { data, error } = await supabase
    .rpc('authorise', { 
      requested_permission: permission,
      tenant_id: tenantId 
    })
    
  if (error) throw error
  return data
}
```

### Example Usage

```typescript
// Create a new tenant
const { data: tenant } = await supabase
  .from('tenants')
  .insert({ name: 'acme' })
  .select()
  .single()

// Assign a role to a user
const { data: role } = await supabase
  .from('tenant_user_roles')
  .insert({
    tenant_id: tenant.id,
    user_id: 'user-uuid',
    role: 'member',
    role_type: 'default'
  })
```

## Example Implementation

Check out the `/examples` directory for a full implementation using:
- Next.js 14 (App Router)
- shadcn/ui
- Tailwind CSS
- TypeScript

The example demonstrates:
- User authentication
- Tenant creation and management
- Role and permission management
- Member invitation system
- Profile management

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - feel free to use this template in your own projects.

### Planned Features

- [ ] Audit logging system where only system can write logs, authorised users can read logs
- [ ] Invite users to join tenants using SMTP and role assignment in the invite
- [ ] Custom roles?