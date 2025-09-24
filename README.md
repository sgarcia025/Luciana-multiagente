# Luciana AI - Multi-Agent Router Platform

Plataforma SaaS multi-tenant para enrutamiento inteligente de leads de WhatsApp con asignación automática a agentes.

## 🚀 Características Implementadas

### ✅ Fase 1 - Sistema Core (COMPLETADO)
- **Autenticación JWT Multi-Rol**: SUPERUSER, ADMIN, AGENT
- **Multi-Tenant**: Aislamiento completo de datos por tenant
- **Asignación Automática**: Round-robin de leads a agentes disponibles
- **Panel Web Responsivo**: Dashboards diferenciados por rol
- **Integración UltraMSG**: Configuración y envío de mensajes WhatsApp

### 🏗️ Arquitectura
- **Backend**: FastAPI + MongoDB + JWT + Motor (async)
- **Frontend**: React 19 + Tailwind CSS + Shadcn UI
- **WhatsApp**: UltraMSG API integration
- **Base de Datos**: MongoDB con modelos optimizados

## 🔐 Credenciales Demo

```
SUPERUSER: admin@system.com / admin123
ADMIN:     admin@tenant1.com / admin123  
AGENT 1:   agent1@tenant1.com / agent123
AGENT 2:   agent2@tenant1.com / agent123
```

## 📊 Funcionalidades por Rol

### SUPERUSER
- ✅ Crear y gestionar tenants
- ✅ Ver métricas globales de la plataforma
- ✅ Crear usuarios ADMIN

### ADMIN (Tenant)
- ✅ Configurar integración WhatsApp (UltraMSG)
- ✅ Crear/gestionar usuarios AGENT
- ✅ Ver todos los leads del tenant
- ✅ Dashboard con métricas del tenant
- ✅ Enviar mensajes de prueba WhatsApp

### AGENT
- ✅ Ver leads asignados
- ✅ Aceptar/rechazar asignaciones
- ✅ Dashboard personal con leads activos
- 🔄 Enviar mensajes a clientes (próximamente)

## 🔗 API Endpoints Principales

### Autenticación
- `POST /api/auth/login` - Iniciar sesión
- `POST /api/auth/register` - Crear usuario (requiere permisos)
- `GET /api/auth/me` - Información del usuario actual

### Leads & Asignaciones
- `POST /api/leads` - Crear lead (requiere X-Tenant-Id header)
- `GET /api/leads` - Listar leads (filtrado por rol)
- `GET /api/assignments` - Listar asignaciones
- `POST /api/assignments/{id}/accept` - Aceptar asignación
- `POST /api/assignments/{id}/decline` - Rechazar asignación

### WhatsApp Integration
- `PATCH /api/whatsapp/config` - Configurar UltraMSG
- `GET /api/whatsapp/status` - Estado de la instancia
- `POST /api/whatsapp/send-message` - Enviar mensaje
- `POST /api/webhooks/whatsapp` - Webhook para mensajes entrantes

## 🛠️ Configuración UltraMSG

1. **Crear cuenta en UltraMSG**
2. **Configurar instancia WhatsApp**
3. **En Luciana AI**:
   - Login como ADMIN
   - Ir a "Configuración"
   - Llenar datos de UltraMSG:
     - API Base URL: `https://api.ultramsg.com/instance{tu_id}`
     - API Key: Tu token de UltraMSG
     - Número WhatsApp: Tu número con código país (+34...)

4. **Configurar Webhook en UltraMSG**:
   ```
   Webhook URL: https://crmwarouter.preview.emergentagent.com/api/webhooks/whatsapp
   ```

## 📝 Flujo de Trabajo

### Creación de Lead (desde Luciana AI)
```bash
curl -X POST https://crmwarouter.preview.emergentagent.com/api/leads \
  -H "X-Tenant-Id: 9b342966-daf6-4962-b8d1-524aa0b0781f" \
  -H "Content-Type: application/json" \
  -d '{
    "external_lead_id": "LUCIANA_001",
    "source": "Luciana AI Chat",
    "customer": {
      "name": "Juan Pérez",
      "phone": "+34612345678",
      "email": "juan@empresa.com"
    },
    "journey_stage": "qualified",
    "priority": "high",
    "metadata": {"intent": "ai_integration"}
  }'
```

### Proceso de Asignación
1. Lead creado → Sistema asigna automáticamente (round-robin)
2. Agente recibe notificación → Acepta/rechaza
3. Si rechaza → Reasigna a siguiente agente
4. Si acepta → Puede comunicarse vía WhatsApp

## 🗂️ Modelos de Datos

### User
```python
{
  "id": "uuid",
  "tenant_id": "uuid", 
  "email": "string",
  "role": "SUPERUSER|ADMIN|AGENT",
  "name": "string",
  "is_active": boolean
}
```

### Lead
```python
{
  "id": "uuid",
  "tenant_id": "uuid",
  "external_lead_id": "string",
  "source": "string",
  "customer": {
    "name": "string",
    "phone": "string",
    "email": "string"
  },
  "journey_stage": "string",
  "priority": "high|medium|low",
  "status": "pending|assigned|accepted|completed",
  "assigned_agent_id": "uuid"
}
```

### Assignment
```python
{
  "id": "uuid",
  "tenant_id": "uuid",
  "lead_id": "uuid", 
  "agent_id": "uuid",
  "status": "pending|accepted|declined|expired",
  "assigned_at": "datetime",
  "expires_at": "datetime"
}
```

## 🚦 Estado del Proyecto

### ✅ Completado
- [x] Sistema de autenticación multi-rol
- [x] Multi-tenancy con aislamiento de datos
- [x] Asignación automática round-robin
- [x] Panel web completo con dashboards
- [x] Integración UltraMSG configuración
- [x] API RESTful completa
- [x] UI responsiva con Shadcn

### 🔄 En Desarrollo (Siguientes Fases)
- [ ] Chat en tiempo real (WebSockets)
- [ ] Subida y gestión de archivos multimedia
- [ ] Plantillas de mensajes predefinidas
- [ ] Métricas avanzadas y reportes
- [ ] Sistema de notas internas
- [ ] Notificaciones push en tiempo real
- [ ] Gestión de equipos y skills
- [ ] SLA y recordatorios automáticos

## 🏃‍♂️ Ejecutar el Proyecto

```bash
# Backend ya está corriendo en supervisor
# Frontend ya está corriendo en supervisor

# Para reiniciar servicios:
sudo supervisorctl restart backend
sudo supervisorctl restart frontend

# Para ver logs:
tail -f /var/log/supervisor/backend.*.log
tail -f /var/log/supervisor/frontend.*.log
```

## 🎯 Próximos Pasos Recomendados

1. **Integrar WhatsApp Real**: Configurar UltraMSG con credenciales reales
2. **Chat Interface**: Implementar interfaz de chat para agentes
3. **Real-time Updates**: WebSockets para notificaciones instantáneas
4. **File Upload**: Sistema de archivos multimedia para WhatsApp
5. **Analytics**: Dashboard con métricas detalladas de conversión

---

**Desarrollado por**: Luciana AI Technology  
**Stack**: FastAPI + React + MongoDB + UltraMSG  
**Versión**: 1.0.0 - MVP Fase 1
