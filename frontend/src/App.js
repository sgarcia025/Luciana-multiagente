import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Card, CardHeader, CardContent, CardTitle } from './components/ui/card';
import { Badge } from './components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Alert, AlertDescription } from './components/ui/alert';
import { Separator } from './components/ui/separator';
import { Avatar, AvatarFallback, AvatarImage } from './components/ui/avatar';
import { Bell, Users, MessageSquare, Settings, CheckCircle, XCircle, Clock, Phone, Mail } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = React.createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchCurrentUser();
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchCurrentUser = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`);
      setUser(response.data);
    } catch (error) {
      console.error('Error fetching user:', error);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    try {
      const response = await axios.post(`${API}/auth/login`, { email, password });
      const { access_token, user: userData } = response.data;
      
      localStorage.setItem('token', access_token);
      setToken(access_token);
      setUser(userData);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      
      return { success: true };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Login failed' 
      };
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Login Component
const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const result = await login(email, password);
    
    if (result.success) {
      // Redirect to dashboard after successful login
      navigate('/');
    } else {
      setError(result.error);
    }
    
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-8">
        {/* Logo */}
        <div className="text-center">
          <div className="mx-auto h-20 w-20 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-xl flex items-center justify-center mb-4">
            <MessageSquare className="h-10 w-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900">Luciana AI</h1>
          <p className="text-gray-600 mt-2">Multi-Agent Router Platform</p>
        </div>

        <Card className="backdrop-blur-lg bg-white/90 border-0 shadow-2xl">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl text-center font-semibold">Iniciar Sesión</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <Alert className="border-red-200 bg-red-50">
                  <AlertDescription className="text-red-700">{error}</AlertDescription>
                </Alert>
              )}
              
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-700">Email</label>
                <Input
                  data-testid="login-email-input"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="tu@email.com"
                  required
                  className="h-11"
                />
              </div>
              
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-700">Contraseña</label>
                <Input
                  data-testid="login-password-input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  className="h-11"
                />
              </div>
              
              <Button 
                data-testid="login-submit-button"
                type="submit" 
                className="w-full h-11 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-medium"
                disabled={loading}
              >
                {loading ? 'Iniciando sesión...' : 'Iniciar Sesión'}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Demo Credentials */}
        <Card className="bg-gray-50 border-gray-200">
          <CardHeader>
            <CardTitle className="text-lg">Credenciales Demo</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="font-medium text-sm">SUPERUSER:</p>
              <p className="text-sm text-gray-600">admin@system.com / admin123</p>
            </div>
            <div>
              <p className="font-medium text-sm">ADMIN:</p>
              <p className="text-sm text-gray-600">admin@tenant1.com / admin123</p>
            </div>
            <div>
              <p className="font-medium text-sm">AGENT:</p>
              <p className="text-sm text-gray-600">agent1@tenant1.com / agent123</p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const { user, logout } = useAuth();
  const [leads, setLeads] = useState([]);
  const [assignments, setAssignments] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedLead, setSelectedLead] = useState(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [leadsRes, assignmentsRes] = await Promise.all([
        axios.get(`${API}/leads`),
        axios.get(`${API}/assignments`)
      ]);
      
      setLeads(leadsRes.data);
      setAssignments(assignmentsRes.data);

      // Fetch users if admin or superuser
      if (user.role === 'ADMIN' || user.role === 'SUPERUSER') {
        const usersRes = await axios.get(`${API}/users`);
        setUsers(usersRes.data);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAcceptAssignment = async (assignmentId) => {
    try {
      await axios.post(`${API}/assignments/${assignmentId}/accept`);
      fetchData(); // Refresh data
    } catch (error) {
      console.error('Error accepting assignment:', error);
    }
  };

  const handleDeclineAssignment = async (assignmentId) => {
    try {
      await axios.post(`${API}/assignments/${assignmentId}/decline`);
      fetchData(); // Refresh data
    } catch (error) {
      console.error('Error declining assignment:', error);
    }
  };

  const getRoleColor = (role) => {
    const colors = {
      SUPERUSER: 'bg-purple-100 text-purple-800',
      ADMIN: 'bg-blue-100 text-blue-800',
      AGENT: 'bg-green-100 text-green-800'
    };
    return colors[role] || 'bg-gray-100 text-gray-800';
  };

  const getStatusColor = (status) => {
    const colors = {
      pending: 'bg-yellow-100 text-yellow-800',
      assigned: 'bg-blue-100 text-blue-800',
      accepted: 'bg-green-100 text-green-800',
      declined: 'bg-red-100 text-red-800',
      completed: 'bg-gray-100 text-gray-800'
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Cargando...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="h-10 w-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center">
                <MessageSquare className="h-6 w-6 text-white" />
              </div>
              <h1 className="text-xl font-bold text-gray-900">Luciana AI</h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <Badge className={getRoleColor(user.role)}>
                {user.role}
              </Badge>
              <div className="flex items-center space-x-2">
                <Avatar className="h-8 w-8">
                  <AvatarFallback className="bg-blue-100 text-blue-700">
                    {user.name.charAt(0).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <span className="text-sm font-medium text-gray-700">{user.name}</span>
              </div>
              <Button 
                data-testid="logout-button"
                variant="outline" 
                size="sm" 
                onClick={logout}
              >
                Salir
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="p-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Leads</p>
                  <p className="text-2xl font-bold text-gray-900">{leads.length}</p>
                </div>
                <Users className="h-8 w-8 text-blue-600" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Asignaciones Pendientes</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {assignments.filter(a => a.status === 'pending').length}
                  </p>
                </div>
                <Clock className="h-8 w-8 text-yellow-600" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Leads Aceptados</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {leads.filter(l => l.status === 'accepted').length}
                  </p>
                </div>
                <CheckCircle className="h-8 w-8 text-green-600" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Usuarios Activos</p>
                  <p className="text-2xl font-bold text-gray-900">{users.length}</p>
                </div>
                <Settings className="h-8 w-8 text-purple-600" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content */}
        <Tabs defaultValue="leads" className="space-y-6">
          <TabsList className="grid w-full grid-cols-5 lg:w-500">
            <TabsTrigger value="leads">Leads</TabsTrigger>
            <TabsTrigger value="assignments">Asignaciones</TabsTrigger>
            {user.role === 'AGENT' && <TabsTrigger value="chat">Chat</TabsTrigger>}
            {(user.role === 'ADMIN' || user.role === 'SUPERUSER') && (
              <TabsTrigger value="users">Usuarios</TabsTrigger>
            )}
            <TabsTrigger value="settings">Configuración</TabsTrigger>
          </TabsList>

          {/* Leads Tab */}
          <TabsContent value="leads" data-testid="leads-tab">
            <div className="space-y-6">
              {(user.role === 'ADMIN' || user.role === 'SUPERUSER') && (
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle>Crear Lead Manual</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <CreateLeadForm users={users} onLeadCreated={fetchData} />
                  </CardContent>
                </Card>
              )}
              
              <Card>
                <CardHeader>
                  <CardTitle>Leads ({leads.length})</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {leads.map((lead) => {
                      const assignedAgent = users.find(u => u.id === lead.assigned_agent_id);
                      return (
                        <div key={lead.id} className="border rounded-lg p-4 bg-white hover:shadow-md transition-shadow">
                          <div className="flex items-start justify-between">
                            <div className="space-y-2 flex-1">
                              <div className="flex items-center space-x-2">
                                <h3 className="font-medium">{lead.customer.name}</h3>
                                <Badge className={getStatusColor(lead.status)}>
                                  {lead.status}
                                </Badge>
                                <Badge variant="outline">{lead.priority}</Badge>
                              </div>
                              <div className="flex items-center space-x-4 text-sm text-gray-600">
                                <div className="flex items-center space-x-1">
                                  <Phone className="h-4 w-4" />
                                  <span>{lead.customer.phone}</span>
                                </div>
                                {lead.customer.email && (
                                  <div className="flex items-center space-x-1">
                                    <Mail className="h-4 w-4" />
                                    <span>{lead.customer.email}</span>
                                  </div>
                                )}
                              </div>
                              <p className="text-sm text-gray-600">
                                Fuente: {lead.source} | Etapa: {lead.journey_stage}
                              </p>
                              <p className="text-xs text-gray-500">
                                Creado: {new Date(lead.created_at).toLocaleString()}
                              </p>
                            </div>
                            
                            <div className="ml-4 text-right space-y-2">
                              {lead.assigned_agent_id && assignedAgent ? (
                                <div className="flex items-center space-x-2">
                                  <Avatar className="h-6 w-6">
                                    <AvatarFallback className="bg-blue-100 text-blue-700 text-xs">
                                      {assignedAgent.name.charAt(0).toUpperCase()}
                                    </AvatarFallback>
                                  </Avatar>
                                  <span className="text-sm font-medium text-blue-700">
                                    {assignedAgent.name}
                                  </span>
                                  {(user.role === 'ADMIN' || user.role === 'SUPERUSER') && (
                                    <ReassignButton lead={lead} users={users} onReassigned={fetchData} />
                                  )}
                                </div>
                              ) : (
                                <div className="flex items-center space-x-2">
                                  <Badge variant="secondary" className="text-xs">
                                    Sin asignar
                                  </Badge>
                                  {(user.role === 'ADMIN' || user.role === 'SUPERUSER') && (
                                    <AssignButton lead={lead} users={users} onAssigned={fetchData} />
                                  )}
                                </div>
                              )}
                              
                              {user.role === 'AGENT' && lead.assigned_agent_id === user.id && lead.status === 'accepted' && (
                                <Button
                                  size="sm"
                                  onClick={() => setSelectedLead(lead)}
                                  className="bg-green-600 hover:bg-green-700"
                                >
                                  <MessageSquare className="h-4 w-4 mr-1" />
                                  Chat
                                </Button>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    {leads.length === 0 && (
                      <div className="text-center py-8 text-gray-500">
                        <Users className="h-12 w-12 mx-auto mb-2 text-gray-300" />
                        <p>No hay leads disponibles</p>
                        <p className="text-sm">Crea tu primer lead manual o espera leads de Luciana AI</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Assignments Tab */}
          <TabsContent value="assignments" data-testid="assignments-tab">
            <Card>
              <CardHeader>
                <CardTitle>Asignaciones ({assignments.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {assignments.map((assignment) => {
                    const lead = leads.find(l => l.id === assignment.lead_id);
                    return (
                      <div key={assignment.id} className="border rounded-lg p-4 bg-white">
                        <div className="flex items-start justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center space-x-2">
                              <h3 className="font-medium">
                                {lead ? lead.customer.name : 'Lead no encontrado'}
                              </h3>
                              <Badge className={getStatusColor(assignment.status)}>
                                {assignment.status}
                              </Badge>
                            </div>
                            <p className="text-sm text-gray-600">
                              Asignado: {new Date(assignment.assigned_at).toLocaleString()}
                            </p>
                            {assignment.status === 'pending' && (
                              <p className="text-sm text-orange-600">
                                Expira: {new Date(assignment.expires_at).toLocaleString()}
                              </p>
                            )}
                          </div>
                          
                          {user.role === 'AGENT' && assignment.status === 'pending' && (
                            <div className="flex space-x-2">
                              <Button
                                data-testid={`accept-assignment-${assignment.id}`}
                                size="sm"
                                onClick={() => handleAcceptAssignment(assignment.id)}
                                className="bg-green-600 hover:bg-green-700"
                              >
                                <CheckCircle className="h-4 w-4 mr-1" />
                                Aceptar
                              </Button>
                              <Button
                                data-testid={`decline-assignment-${assignment.id}`}
                                size="sm"
                                variant="destructive"
                                onClick={() => handleDeclineAssignment(assignment.id)}
                              >
                                <XCircle className="h-4 w-4 mr-1" />
                                Rechazar
                              </Button>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                  {assignments.length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      No hay asignaciones disponibles
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Chat Tab (Agent only) */}
          {user.role === 'AGENT' && (
            <TabsContent value="chat" data-testid="chat-tab">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">
                {/* Chat List */}
                <Card className="lg:col-span-1">
                  <CardHeader>
                    <CardTitle>Conversaciones Activas</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <div className="space-y-1 max-h-[500px] overflow-y-auto">
                      {leads.filter(lead => lead.assigned_agent_id === user.id && lead.status === 'accepted').map((lead) => (
                        <div
                          key={lead.id}
                          onClick={() => setSelectedLead(lead)}
                          className={`p-3 border-b cursor-pointer hover:bg-gray-50 transition-colors ${
                            selectedLead?.id === lead.id ? 'bg-blue-50 border-blue-200' : ''
                          }`}
                        >
                          <div className="flex items-start space-x-3">
                            <Avatar className="h-10 w-10">
                              <AvatarFallback className="bg-green-100 text-green-700">
                                {lead.customer.name.charAt(0).toUpperCase()}
                              </AvatarFallback>
                            </Avatar>
                            <div className="flex-1 min-w-0">
                              <p className="font-medium text-sm truncate">{lead.customer.name}</p>
                              <p className="text-xs text-gray-500">{lead.customer.phone}</p>
                              <p className="text-xs text-gray-400 mt-1">{lead.source}</p>
                            </div>
                            <div className="flex flex-col items-end">
                              <Badge className="text-xs bg-green-100 text-green-800">
                                Activo
                              </Badge>
                            </div>
                          </div>
                        </div>
                      ))}
                      {leads.filter(lead => lead.assigned_agent_id === user.id && lead.status === 'accepted').length === 0 && (
                        <div className="p-6 text-center text-gray-500">
                          <MessageSquare className="h-12 w-12 mx-auto mb-2 text-gray-300" />
                          <p>No hay conversaciones activas</p>
                          <p className="text-sm">Acepta asignaciones para comenzar a chatear</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                {/* Chat Interface */}
                <Card className="lg:col-span-2">
                  {selectedLead ? (
                    <ChatInterface 
                      lead={selectedLead} 
                      user={user} 
                      onMessageSent={() => {
                        // Refresh data or handle real-time updates
                      }}
                    />
                  ) : (
                    <div className="flex items-center justify-center h-full">
                      <div className="text-center text-gray-500">
                        <MessageSquare className="h-16 w-16 mx-auto mb-4 text-gray-300" />
                        <h3 className="text-lg font-medium">Selecciona una conversación</h3>
                        <p>Elige un lead de la lista para comenzar a chatear por WhatsApp</p>
                      </div>
                    </div>
                  )}
                </Card>
              </div>
            </TabsContent>
          )}

          {/* Users Tab (Admin/Superuser only) */}
          {(user.role === 'ADMIN' || user.role === 'SUPERUSER') && (
            <TabsContent value="users" data-testid="users-tab">
              <UserManagement 
                user={user} 
                users={users} 
                leads={leads}
                onUserCreated={fetchData}
              />
            </TabsContent>
          )}

          {/* Settings Tab */}
          <TabsContent value="settings" data-testid="settings-tab">
            <Card>
              <CardHeader>
                <CardTitle>Configuración de WhatsApp</CardTitle>
              </CardHeader>
              <CardContent>
                <WhatsAppSettings user={user} />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

// Create Lead Form Component
const CreateLeadForm = ({ users, onLeadCreated }) => {
  const [formData, setFormData] = useState({
    external_lead_id: '',
    source: 'Manual Creation',
    customer: {
      name: '',
      phone: '',
      email: ''
    },
    journey_stage: 'new',
    priority: 'medium',
    assigned_agent_id: ''
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [expanded, setExpanded] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const submitData = {
        external_lead_id: formData.external_lead_id || `MANUAL_${Date.now()}`,
        source: formData.source,
        customer: formData.customer,
        journey_stage: formData.journey_stage,
        priority: formData.priority,
        metadata: { created_manually: true }
      };

      const url = formData.assigned_agent_id 
        ? `${API}/leads/manual?assigned_agent_id=${formData.assigned_agent_id}`
        : `${API}/leads/manual`;

      const response = await axios.post(url, submitData);
      
      setMessage('Lead creado exitosamente');
      setFormData({
        external_lead_id: '',
        source: 'Manual Creation',
        customer: { name: '', phone: '', email: '' },
        journey_stage: 'new',
        priority: 'medium',
        assigned_agent_id: ''
      });
      setExpanded(false);
      onLeadCreated();
    } catch (error) {
      setMessage(error.response?.data?.detail || 'Error al crear lead');
    } finally {
      setLoading(false);
    }
  };

  const agents = users.filter(u => u.role === 'AGENT' && u.is_active);

  if (!expanded) {
    return (
      <Button 
        onClick={() => setExpanded(true)}
        className="w-full bg-blue-600 hover:bg-blue-700"
      >
        <Users className="h-4 w-4 mr-2" />
        Crear Nuevo Lead
      </Button>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-sm font-medium text-gray-700">Nombre del Cliente *</label>
          <Input
            value={formData.customer.name}
            onChange={(e) => setFormData({
              ...formData,
              customer: { ...formData.customer, name: e.target.value }
            })}
            placeholder="Ej: Juan Pérez"
            required
          />
        </div>
        <div>
          <label className="text-sm font-medium text-gray-700">Teléfono *</label>
          <Input
            value={formData.customer.phone}
            onChange={(e) => setFormData({
              ...formData,
              customer: { ...formData.customer, phone: e.target.value }
            })}
            placeholder="+34612345678"
            required
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-sm font-medium text-gray-700">Email</label>
          <Input
            type="email"
            value={formData.customer.email}
            onChange={(e) => setFormData({
              ...formData,
              customer: { ...formData.customer, email: e.target.value }
            })}
            placeholder="juan@empresa.com"
          />
        </div>
        <div>
          <label className="text-sm font-medium text-gray-700">Fuente</label>
          <Input
            value={formData.source}
            onChange={(e) => setFormData({ ...formData, source: e.target.value })}
            placeholder="Ej: LinkedIn, Web, Referido"
          />
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="text-sm font-medium text-gray-700">Etapa</label>
          <select
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={formData.journey_stage}
            onChange={(e) => setFormData({ ...formData, journey_stage: e.target.value })}
          >
            <option value="new">Nuevo</option>
            <option value="contacted">Contactado</option>
            <option value="qualified">Calificado</option>
            <option value="proposal">Propuesta</option>
            <option value="negotiation">Negociación</option>
          </select>
        </div>
        <div>
          <label className="text-sm font-medium text-gray-700">Prioridad</label>
          <select
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={formData.priority}
            onChange={(e) => setFormData({ ...formData, priority: e.target.value })}
          >
            <option value="low">Baja</option>
            <option value="medium">Media</option>
            <option value="high">Alta</option>
          </select>
        </div>
        <div>
          <label className="text-sm font-medium text-gray-700">Asignar a Agente</label>
          <select
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={formData.assigned_agent_id}
            onChange={(e) => setFormData({ ...formData, assigned_agent_id: e.target.value })}
          >
            <option value="">Auto-asignar</option>
            {agents.map(agent => (
              <option key={agent.id} value={agent.id}>
                {agent.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {message && (
        <Alert className={message.includes('Error') ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}>
          <AlertDescription className={message.includes('Error') ? 'text-red-700' : 'text-green-700'}>
            {message}
          </AlertDescription>
        </Alert>
      )}

      <div className="flex space-x-3">
        <Button 
          type="submit" 
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700"
        >
          {loading ? 'Creando...' : 'Crear Lead'}
        </Button>
        <Button 
          type="button" 
          variant="outline"
          onClick={() => {
            setExpanded(false);
            setMessage('');
          }}
        >
          Cancelar
        </Button>
      </div>
    </form>
  );
};

// Reassign Button Component
const ReassignButton = ({ lead, users, onReassigned }) => {
  const [showDropdown, setShowDropdown] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleReassign = async (agentId) => {
    setLoading(true);
    try {
      await axios.patch(`${API}/leads/${lead.id}/assign?agent_id=${agentId}`);
      onReassigned();
      setShowDropdown(false);
    } catch (error) {
      alert(`Error al reasignar: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const agents = users.filter(u => u.role === 'AGENT' && u.is_active && u.id !== lead.assigned_agent_id);

  return (
    <div className="relative">
      <Button
        size="sm"
        variant="outline"
        onClick={() => setShowDropdown(!showDropdown)}
        disabled={loading}
      >
        Reasignar
      </Button>
      {showDropdown && (
        <div className="absolute right-0 mt-1 w-48 bg-white border border-gray-300 rounded-md shadow-lg z-10">
          <div className="py-1">
            {agents.map(agent => (
              <button
                key={agent.id}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                onClick={() => handleReassign(agent.id)}
              >
                {agent.name}
              </button>
            ))}
            <button
              className="block w-full text-left px-4 py-2 text-sm text-gray-500 hover:bg-gray-100"
              onClick={() => setShowDropdown(false)}
            >
              Cancelar
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// Assign Button Component
const AssignButton = ({ lead, users, onAssigned }) => {
  const [showDropdown, setShowDropdown] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleAssign = async (agentId) => {
    setLoading(true);
    try {
      await axios.patch(`${API}/leads/${lead.id}/assign?agent_id=${agentId}`);
      onAssigned();
      setShowDropdown(false);
    } catch (error) {
      alert(`Error al asignar: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const agents = users.filter(u => u.role === 'AGENT' && u.is_active);

  return (
    <div className="relative">
      <Button
        size="sm"
        onClick={() => setShowDropdown(!showDropdown)}
        disabled={loading}
        className="bg-green-600 hover:bg-green-700 text-white"
      >
        Asignar
      </Button>
      {showDropdown && (
        <div className="absolute right-0 mt-1 w-48 bg-white border border-gray-300 rounded-md shadow-lg z-10">
          <div className="py-1">
            {agents.map(agent => (
              <button
                key={agent.id}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                onClick={() => handleAssign(agent.id)}
              >
                {agent.name}
              </button>
            ))}
            <button
              className="block w-full text-left px-4 py-2 text-sm text-gray-500 hover:bg-gray-100"
              onClick={() => setShowDropdown(false)}
            >
              Cancelar
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// Chat Interface Component
const ChatInterface = ({ lead, user, onMessageSent }) => {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingMessages, setLoadingMessages] = useState(true);

  useEffect(() => {
    if (lead) {
      fetchMessages();
    }
  }, [lead]);

  const fetchMessages = async () => {
    try {
      setLoadingMessages(true);
      const response = await axios.get(`${API}/conversations/${lead.id}/messages`);
      setMessages(response.data);
    } catch (error) {
      console.error('Error fetching messages:', error);
    } finally {
      setLoadingMessages(false);
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!newMessage.trim() || loading) return;

    setLoading(true);
    try {
      const response = await axios.post(`${API}/conversations/${lead.id}/messages`, {
        text: newMessage,
        type: 'text'
      });
      
      setMessages([...messages, response.data]);
      setNewMessage('');
      onMessageSent();
    } catch (error) {
      alert(`Error al enviar mensaje: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <CardHeader className="border-b">
        <div className="flex items-center space-x-3">
          <Avatar className="h-10 w-10">
            <AvatarFallback className="bg-green-100 text-green-700">
              {lead.customer.name.charAt(0).toUpperCase()}
            </AvatarFallback>
          </Avatar>
          <div>
            <CardTitle className="text-lg">{lead.customer.name}</CardTitle>
            <p className="text-sm text-gray-600">{lead.customer.phone}</p>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="flex flex-col h-[440px]">
        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto space-y-3 mb-4 bg-gray-50 p-4 rounded-lg">
          {loadingMessages ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
            </div>
          ) : messages.length > 0 ? (
            messages.map((message) => (
              <div
                key={message.id}
                className={`flex ${message.direction === 'out' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                    message.direction === 'out'
                      ? 'bg-blue-600 text-white chat-bubble-out'
                      : 'bg-white text-gray-800 border chat-bubble-in'
                  }`}
                >
                  <p className="text-sm">{message.text}</p>
                  <p className={`text-xs mt-1 ${
                    message.direction === 'out' ? 'text-blue-100' : 'text-gray-500'
                  }`}>
                    {new Date(message.created_at).toLocaleTimeString()}
                  </p>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-8 text-gray-500">
              <MessageSquare className="h-12 w-12 mx-auto mb-2 text-gray-300" />
              <p>No hay mensajes aún</p>
              <p className="text-sm">Envía tu primer mensaje por WhatsApp</p>
            </div>
          )}
        </div>

        {/* Message Input */}
        <form onSubmit={sendMessage} className="flex space-x-2">
          <Input
            value={newMessage}
            onChange={(e) => setNewMessage(e.target.value)}
            placeholder="Escribe tu mensaje..."
            disabled={loading}
            className="flex-1"
          />
          <Button 
            type="submit" 
            disabled={loading || !newMessage.trim()}
            className="bg-green-600 hover:bg-green-700"
          >
            {loading ? (
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
            ) : (
              'Enviar'
            )}
          </Button>
        </form>
      </CardContent>
    </>
  );
};

// User Management Component  
const UserManagement = ({ user, users, leads, onUserCreated }) => {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newUser, setNewUser] = useState({
    name: '',
    email: '',
    password: '',
    role: 'AGENT'
  });
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState('');

  const getRoleColor = (role) => {
    const colors = {
      SUPERUSER: 'bg-purple-100 text-purple-800',
      ADMIN: 'bg-blue-100 text-blue-800',
      AGENT: 'bg-green-100 text-green-800'
    };
    return colors[role] || 'bg-gray-100 text-gray-800';
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setCreating(true);
    setMessage('');

    try {
      await axios.post(`${API}/auth/register`, newUser);
      setMessage('Usuario creado exitosamente');
      setNewUser({ name: '', email: '', password: '', role: 'AGENT' });
      setShowCreateForm(false);
      onUserCreated();
    } catch (error) {
      setMessage(error.response?.data?.detail || 'Error al crear usuario');
    } finally {
      setCreating(false);
    }
  };

  const getRoleOptions = () => {
    if (user.role === 'SUPERUSER') {
      return [
        { value: 'SUPERUSER', label: 'Super Usuario' },
        { value: 'ADMIN', label: 'Administrador' },
        { value: 'AGENT', label: 'Agente' }
      ];
    } else {
      return [
        { value: 'ADMIN', label: 'Administrador' },
        { value: 'AGENT', label: 'Agente' }
      ];
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Usuarios ({users.length})</CardTitle>
            <Button 
              onClick={() => setShowCreateForm(!showCreateForm)}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <Users className="h-4 w-4 mr-2" />
              Crear Usuario
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {showCreateForm && (
            <div className="mb-6 p-4 border rounded-lg bg-gray-50">
              <h3 className="text-lg font-medium mb-4">Crear Nuevo Usuario</h3>
              <form onSubmit={handleCreateUser} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-700">Nombre Completo</label>
                    <Input
                      value={newUser.name}
                      onChange={(e) => setNewUser({...newUser, name: e.target.value})}
                      placeholder="Ej: María González"
                      required
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-700">Email</label>
                    <Input
                      type="email"
                      value={newUser.email}
                      onChange={(e) => setNewUser({...newUser, email: e.target.value})}
                      placeholder="maria@empresa.com"
                      required
                    />
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-700">Contraseña</label>
                    <Input
                      type="password"
                      value={newUser.password}
                      onChange={(e) => setNewUser({...newUser, password: e.target.value})}
                      placeholder="••••••••"
                      minLength={6}
                      required
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-700">Rol</label>
                    <select
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      value={newUser.role}
                      onChange={(e) => setNewUser({...newUser, role: e.target.value})}
                    >
                      {getRoleOptions().map(option => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {message && (
                  <Alert className={message.includes('Error') ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}>
                    <AlertDescription className={message.includes('Error') ? 'text-red-700' : 'text-green-700'}>
                      {message}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="flex space-x-3">
                  <Button 
                    type="submit" 
                    disabled={creating}
                    className="bg-blue-600 hover:bg-blue-700"
                  >
                    {creating ? 'Creando...' : 'Crear Usuario'}
                  </Button>
                  <Button 
                    type="button" 
                    variant="outline"
                    onClick={() => {
                      setShowCreateForm(false);
                      setMessage('');
                      setNewUser({ name: '', email: '', password: '', role: 'AGENT' });
                    }}
                  >
                    Cancelar
                  </Button>
                </div>
              </form>
            </div>
          )}

          <div className="space-y-4">
            {users.map((u) => {
              const assignedLeadsCount = users.length > 0 ? 
                leads.filter(lead => lead.assigned_agent_id === u.id).length : 0;
              
              return (
                <div key={u.id} className="border rounded-lg p-4 bg-white hover:shadow-md transition-shadow">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Avatar>
                        <AvatarFallback className="bg-blue-100 text-blue-700">
                          {u.name.charAt(0).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <div>
                        <h3 className="font-medium">{u.name}</h3>
                        <p className="text-sm text-gray-600">{u.email}</p>
                        {u.role === 'AGENT' && (
                          <p className="text-xs text-gray-500">
                            {assignedLeadsCount} leads asignados
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge className={getRoleColor(u.role)}>
                        {u.role === 'SUPERUSER' ? 'SUPER' : u.role}
                      </Badge>
                      <Badge variant={u.is_active ? "default" : "secondary"}>
                        {u.is_active ? "Activo" : "Inactivo"}
                      </Badge>
                    </div>
                  </div>
                </div>
              );
            })}
            {users.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <Users className="h-12 w-12 mx-auto mb-2 text-gray-300" />
                <p>No hay usuarios disponibles</p>
                <p className="text-sm">Crea tu primer usuario para comenzar</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// WhatsApp Settings Component
const WhatsAppSettings = ({ user }) => {
  const [config, setConfig] = useState({
    api_base: '',
    api_key: '',
    phone_number: ''
  });
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [message, setMessage] = useState('');

  const handleConfigSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const response = await axios.patch(`${API}/whatsapp/config`, config);
      setMessage('Configuración guardada exitosamente');
      
      // Check status after saving
      checkWhatsAppStatus();
    } catch (error) {
      setMessage(error.response?.data?.detail || 'Error al guardar la configuración');
    } finally {
      setLoading(false);
    }
  };

  const checkWhatsAppStatus = async () => {
    try {
      const response = await axios.get(`${API}/whatsapp/status`);
      setStatus(response.data);
    } catch (error) {
      console.error('Error checking WhatsApp status:', error);
    }
  };

  const sendTestMessage = async () => {
    const testPhone = prompt('Ingresa el número de teléfono para enviar mensaje de prueba (incluye código de país):');
    if (!testPhone) return;

    try {
      const response = await axios.post(`${API}/whatsapp/send-message`, {
        to_phone: testPhone,
        message: '¡Hola! Este es un mensaje de prueba desde tu WhatsApp CRM de Luciana AI Technology. 🚀',
        type: 'text'
      });

      if (response.data.success) {
        alert('Mensaje de prueba enviado exitosamente!');
      } else {
        alert(`Error al enviar mensaje: ${response.data.error}`);
      }
    } catch (error) {
      alert(`Error al enviar mensaje: ${error.response?.data?.detail || error.message}`);
    }
  };

  if (user.role === 'AGENT') {
    return (
      <Alert>
        <Settings className="h-4 w-4" />
        <AlertDescription>
          Solo los administradores pueden configurar la integración de WhatsApp.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-6">
      <Alert className="border-blue-200 bg-blue-50">
        <Settings className="h-4 w-4 text-blue-600" />
        <AlertDescription className="text-blue-800">
          Configura tu integración con UltraMSG para enviar y recibir mensajes de WhatsApp.
          <br />
          <strong>Nota:</strong> Necesitas una cuenta activa en UltraMSG y tu instancia configurada.
        </AlertDescription>
      </Alert>

      <form onSubmit={handleConfigSubmit} className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-700">API Base URL *</label>
            <Input
              data-testid="whatsapp-api-base"
              placeholder="https://api.ultramsg.com/instance123456"
              value={config.api_base}
              onChange={(e) => setConfig({...config, api_base: e.target.value})}
              required
            />
            <p className="text-xs text-gray-500">
              URL base de tu instancia de UltraMSG
            </p>
          </div>
          
          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-700">API Key *</label>
            <Input
              data-testid="whatsapp-api-key"
              type="password"
              placeholder="Tu token de UltraMSG"
              value={config.api_key}
              onChange={(e) => setConfig({...config, api_key: e.target.value})}
              required
            />
            <p className="text-xs text-gray-500">
              Token de acceso de UltraMSG
            </p>
          </div>
        </div>
        
        <div className="space-y-2">
          <label className="text-sm font-medium text-gray-700">Número de WhatsApp *</label>
          <Input
            data-testid="whatsapp-phone-number"
            placeholder="+34612345678"
            value={config.phone_number}
            onChange={(e) => setConfig({...config, phone_number: e.target.value})}
            required
          />
          <p className="text-xs text-gray-500">
            Número de WhatsApp conectado a la instancia (incluye código de país)
          </p>
        </div>

        {message && (
          <Alert className={message.includes('Error') ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}>
            <AlertDescription className={message.includes('Error') ? 'text-red-700' : 'text-green-700'}>
              {message}
            </AlertDescription>
          </Alert>
        )}

        <div className="flex gap-3">
          <Button 
            data-testid="save-whatsapp-config"
            type="submit" 
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-700"
          >
            {loading ? 'Guardando...' : 'Guardar Configuración'}
          </Button>
          
          <Button 
            type="button"
            variant="outline"
            onClick={checkWhatsAppStatus}
          >
            Verificar Estado
          </Button>
          
          <Button 
            type="button"
            variant="outline"
            onClick={sendTestMessage}
            disabled={!config.api_key}
          >
            Enviar Mensaje de Prueba
          </Button>
        </div>
      </form>

      {status && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Estado de WhatsApp</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-medium">Estado de la cuenta:</span>
                <Badge className={status.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>
                  {status.success ? status.status || 'Conectado' : 'Error'}
                </Badge>
              </div>
              
              {status.phone && (
                <div className="flex items-center justify-between">
                  <span className="font-medium">Número:</span>
                  <span>{status.phone}</span>
                </div>
              )}
              
              {status.instance && (
                <div className="flex items-center justify-between">
                  <span className="font-medium">Instancia:</span>
                  <span className="font-mono text-sm">{status.instance}</span>
                </div>
              )}
              
              {!status.success && (
                <Alert className="border-red-200 bg-red-50">
                  <AlertDescription className="text-red-700">
                    {status.error || 'Error al verificar el estado de WhatsApp'}
                  </AlertDescription>
                </Alert>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Configuración de Webhook</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-gray-600">
            Para recibir mensajes entrantes, configura esta URL en tu panel de UltraMSG:
          </p>
          <div className="flex items-center space-x-2">
            <Input
              readOnly
              value={`${BACKEND_URL}/api/webhooks/whatsapp`}
              className="font-mono text-sm bg-gray-50"
            />
            <Button
              size="sm"
              variant="outline"
              onClick={() => navigator.clipboard.writeText(`${BACKEND_URL}/api/webhooks/whatsapp`)}
            >
              Copiar
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return user ? children : <Navigate to="/login" />;
};

// Main App Component
function App() {
  return (
    <div className="App">
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route 
              path="/" 
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              } 
            />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </div>
  );
}

export default App;