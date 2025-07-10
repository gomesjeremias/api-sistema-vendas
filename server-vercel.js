const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Carregar variáveis de ambiente
dotenv.config();

const app = express();
const prisma = new PrismaClient();

// Middlewares
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso requerido' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Rotas de autenticação
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Verificar se o usuário já existe
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Usuário já existe' });
    }

    // Hash da senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Criar usuário
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name
      }
    });

    res.status(201).json({ message: 'Usuário criado com sucesso', userId: user.id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Buscar usuário
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Verificar senha
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Gerar token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rotas de clientes
app.get('/api/clientes', authenticateToken, async (req, res) => {
  try {
    const clientes = await prisma.cliente.findMany({
      orderBy: { createdAt: 'desc' }
    });
    res.json(clientes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar clientes' });
  }
});

app.post('/api/clientes', authenticateToken, async (req, res) => {
  try {
    const { nome, email, telefone, endereco, cpfCnpj } = req.body;
    
    const cliente = await prisma.cliente.create({
      data: { nome, email, telefone, endereco, cpfCnpj }
    });
    
    res.status(201).json(cliente);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao criar cliente' });
  }
});

// Rotas de fornecedores
app.get('/api/fornecedores', authenticateToken, async (req, res) => {
  try {
    const fornecedores = await prisma.fornecedor.findMany({
      orderBy: { createdAt: 'desc' }
    });
    res.json(fornecedores);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar fornecedores' });
  }
});

app.post('/api/fornecedores', authenticateToken, async (req, res) => {
  try {
    const { nome, email, telefone, endereco, cnpj } = req.body;
    
    const fornecedor = await prisma.fornecedor.create({
      data: { nome, email, telefone, endereco, cnpj }
    });
    
    res.status(201).json(fornecedor);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao criar fornecedor' });
  }
});

// Rotas de produtos
app.get('/api/produtos', authenticateToken, async (req, res) => {
  try {
    const produtos = await prisma.produto.findMany({
      include: { fornecedor: true },
      orderBy: { createdAt: 'desc' }
    });
    res.json(produtos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar produtos' });
  }
});

app.post('/api/produtos', authenticateToken, async (req, res) => {
  try {
    const { nome, descricao, preco, categoria, estoque, fornecedorId } = req.body;
    
    const produto = await prisma.produto.create({
      data: { nome, descricao, preco, categoria, estoque, fornecedorId },
      include: { fornecedor: true }
    });
    
    res.status(201).json(produto);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao criar produto' });
  }
});

// Rotas de vendas
app.get('/api/vendas', authenticateToken, async (req, res) => {
  try {
    const vendas = await prisma.venda.findMany({
      include: {
        cliente: true,
        itens: {
          include: { produto: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
    res.json(vendas);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar vendas' });
  }
});

// Dashboard
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const totalClientes = await prisma.cliente.count();
    const totalProdutos = await prisma.produto.count();
    const totalVendas = await prisma.venda.count();
    const totalFornecedores = await prisma.fornecedor.count();

    const vendasRecentes = await prisma.venda.findMany({
      take: 5,
      include: { cliente: true },
      orderBy: { createdAt: 'desc' }
    });

    res.json({
      totalClientes,
      totalProdutos,
      totalVendas,
      totalFornecedores,
      vendasRecentes
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar dados do dashboard' });
  }
});

// Rota de teste
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'API funcionando corretamente' });
});

// Rota raiz
app.get('/', (req, res) => {
  res.json({ 
    message: 'Sistema de Vendas API', 
    version: '1.0.0',
    endpoints: [
      'POST /api/auth/register',
      'POST /api/auth/login',
      'GET /api/clientes',
      'POST /api/clientes',
      'GET /api/fornecedores',
      'POST /api/fornecedores',
      'GET /api/produtos',
      'POST /api/produtos',
      'GET /api/vendas',
      'GET /api/dashboard',
      'GET /api/health'
    ]
  });
});

// Middleware de tratamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Algo deu errado!' });
});

// Para desenvolvimento local
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando na porta ${PORT}`);
  });
}

module.exports = app;

