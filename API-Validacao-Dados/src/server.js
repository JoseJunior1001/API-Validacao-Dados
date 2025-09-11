import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { createClient } from 'redis';

const app = express();

// Configurações
const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379'
};

// Middlewares avançados
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"]
    }
  }
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

app.use(morgan(config.nodeEnv === 'production' ? 'combined' : 'dev'));

// Rate limiting com Redis para distribuição
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // limite por IP
  message: { error: 'Muitas requisições, tente novamente mais tarde.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Cache com Redis
let redisClient;
if (process.env.USE_REDIS === 'true') {
  redisClient = createClient({ url: config.redisUrl });
  redisClient.on('error', (err) => console.log('Redis Client Error', err));
  redisClient.connect();
}

// Utils melhorados
const onlyDigits = (s = '') => (s || '').toString().replace(/\D+/g, '');
const isRepeated = (digits, minLength = 11) => {
  if (digits.length < minLength) return false;
  return new RegExp(`^(\\d)\\1{${minLength - 1},}$`).test(digits);
};

// Validações melhoradas com melhor tratamento de erros
class ValidationError extends Error {
  constructor(message, code = 'VALIDATION_ERROR') {
    super(message);
    this.code = code;
  }
}

// CPF com validação completa
function validateCPF(raw) {
  try {
    const digits = onlyDigits(raw);
    
    if (digits.length !== 11) {
      throw new ValidationError('CPF deve ter exatamente 11 dígitos', 'INVALID_LENGTH');
    }
    
    if (isRepeated(digits)) {
      throw new ValidationError('CPF inválido (sequência repetida)', 'REPEATED_SEQUENCE');
    }

    let sum = 0;
    for (let i = 0; i < 9; i++) {
      sum += parseInt(digits[i]) * (10 - i);
    }
    
    let remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    
    if (remainder !== parseInt(digits[9])) {
      throw new ValidationError('Dígito verificador inválido', 'INVALID_CHECK_DIGIT');
    }

    sum = 0;
    for (let i = 0; i < 10; i++) {
      sum += parseInt(digits[i]) * (11 - i);
    }
    
    remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    
    if (remainder !== parseInt(digits[10])) {
      throw new ValidationError('Dígito verificador inválido', 'INVALID_CHECK_DIGIT');
    }

    const normalized = `${digits.slice(0, 3)}.${digits.slice(3, 6)}.${digits.slice(6, 9)}-${digits.slice(9)}`;
    
    return {
      valid: true,
      normalized,
      metadata: {
        region: getCPFRegion(digits),
        isTemporary: digits.endsWith('0001')
      }
    };
  } catch (error) {
    return {
      valid: false,
      errors: [error.message],
      errorCode: error.code,
      input: raw
    };
  }
}

function getCPFRegion(digits) {
  const regionCodes = {
    '1': 'DF, GO, MS, MT, TO',
    '2': 'AC, AM, AP, PA, RO, RR',
    '3': 'CE, MA, PI',
    '4': 'AL, PB, PE, RN',
    '5': 'BA, SE',
    '6': 'MG',
    '7': 'ES, RJ',
    '8': 'SP',
    '9': 'PR, SC',
    '0': 'RS'
  };
  return regionCodes[digits[8]] || 'Região desconhecida';
}

// CNPJ com validação completa
function validateCNPJ(raw) {
  try {
    const digits = onlyDigits(raw);
    
    if (digits.length !== 14) {
      throw new ValidationError('CNPJ deve ter exatamente 14 dígitos', 'INVALID_LENGTH');
    }
    
    if (isRepeated(digits, 14)) {
      throw new ValidationError('CNPJ inválido (sequência repetida)', 'REPEATED_SEQUENCE');
    }

    const weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

    const calcDigit = (weights, base) => {
      let sum = 0;
      for (let i = 0; i < weights.length; i++) {
        sum += parseInt(base[i]) * weights[i];
      }
      const remainder = sum % 11;
      return remainder < 2 ? 0 : 11 - remainder;
    };

    const digit1 = calcDigit(weights1, digits.slice(0, 12));
    const digit2 = calcDigit(weights2, digits.slice(0, 13));

    if (digit1 !== parseInt(digits[12]) || digit2 !== parseInt(digits[13])) {
      throw new ValidationError('Dígitos verificadores inválidos', 'INVALID_CHECK_DIGIT');
    }

    const normalized = `${digits.slice(0, 2)}.${digits.slice(2, 5)}.${digits.slice(5, 8)}/${digits.slice(8, 12)}-${digits.slice(12)}`;
    
    return {
      valid: true,
      normalized,
      metadata: {
        estado: digits.slice(0, 2),
        sequencial: digits.slice(2, 8),
        filial: digits.slice(8, 12)
      }
    };
  } catch (error) {
    return {
      valid: false,
      errors: [error.message],
      errorCode: error.code,
      input: raw
    };
  }
}

// Email com validação mais robusta
function validateEmail(raw) {
  try {
    const s = (raw || '').toString().trim();
    
    if (!s) {
      throw new ValidationError('E-mail não informado', 'MISSING_EMAIL');
    }
    
    if (s.length > 254) {
      throw new ValidationError('E-mail muito longo', 'EMAIL_TOO_LONG');
    }

    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(s)) {
      throw new ValidationError('Formato de e-mail inválido', 'INVALID_FORMAT');
    }

    const [localPart, domain] = s.split('@');
    
    if (localPart.length > 64) {
      throw new ValidationError('Parte local do e-mail muito longa', 'LOCAL_PART_TOO_LONG');
    }

    return {
      valid: true,
      normalized: s.toLowerCase(),
      metadata: {
        domain: domain.toLowerCase(),
        isDisposable: checkDisposableEmail(domain)
      }
    };
  } catch (error) {
    return {
      valid: false,
      errors: [error.message],
      errorCode: error.code,
      input: raw
    };
  }
}

function checkDisposableEmail(domain) {
  const disposableDomains = new Set([
    'tempmail.com', 'disposable.com', 'throwaway.com' // Adicione mais domínios descartáveis
  ]);
  return disposableDomains.has(domain.toLowerCase());
}

// Password com política configurável
function validatePassword(raw, policy = {}) {
  try {
    const s = (raw || '').toString();
    const errors = [];

    const {
      minLength = 8,
      maxLength = 128,
      requireUpper = true,
      requireLower = true,
      requireNumber = true,
      requireSymbol = true,
      forbidCommon = true,
      customRegex
    } = policy;

    if (s.length < minLength) errors.push(`Senha deve ter no mínimo ${minLength} caracteres`);
    if (s.length > maxLength) errors.push(`Senha deve ter no máximo ${maxLength} caracteres`);
    if (requireUpper && !/[A-Z]/.test(s)) errors.push('Ao menos 1 letra maiúscula');
    if (requireLower && !/[a-z]/.test(s)) errors.push('Ao menos 1 letra minúscula');
    if (requireNumber && !/\d/.test(s)) errors.push('Ao menos 1 número');
    if (requireSymbol && !/[!@#$%^&*(),.?":{}|<>]/.test(s)) errors.push('Ao menos 1 símbolo');
    if (customRegex && !new RegExp(customRegex).test(s)) errors.push('Não atende aos requisitos personalizados');
    
    if (forbidCommon) {
      const commonPasswords = new Set([
        '123456', 'password', '123456789', 'qwerty', 'abc123', '111111', '123123'
      ]);
      if (commonPasswords.has(s.toLowerCase())) {
        errors.push('Senha muito comum');
      }
    }

    if (errors.length > 0) {
      throw new ValidationError(errors.join(', '), 'PASSWORD_POLICY_VIOLATION');
    }

    return {
      valid: true,
      normalized: '***', // Nunca retornar a senha real
      strength: calculatePasswordStrength(s),
      metadata: {
        length: s.length,
        hasUpper: /[A-Z]/.test(s),
        hasLower: /[a-z]/.test(s),
        hasNumber: /\d/.test(s),
        hasSymbol: /[!@#$%^&*(),.?":{}|<>]/.test(s)
      }
    };
  } catch (error) {
    return {
      valid: false,
      errors: error.message.split(', '),
      errorCode: error.code,
      input: '***'
    };
  }
}

function calculatePasswordStrength(password) {
  let strength = 0;
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[a-z]/.test(password)) strength++;
  if (/\d/.test(password)) strength++;
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength++;
  return Math.min(strength, 5); // Máximo 5
}

// Middleware de cache
async function cacheMiddleware(req, res, next) {
  if (config.nodeEnv !== 'production' || !redisClient) return next();
  
  const key = `validate:${req.originalUrl}:${JSON.stringify(req.body)}`;
  
  try {
    const cached = await redisClient.get(key);
    if (cached) {
      return res.json(JSON.parse(cached));
    }
    res.originalJson = res.json;
    res.json = (data) => {
      redisClient.setEx(key, 300, JSON.stringify(data)); // Cache por 5 minutos
      res.originalJson(data);
    };
    next();
  } catch (error) {
    console.error('Cache error:', error);
    next();
  }
}

// Endpoints melhorados
app.get('/health', async (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    redis: redisClient ? 'connected' : 'disabled'
  };
  res.json(health);
});

app.get('/validate/:type?', cacheMiddleware, (req, res) => {
  const { value, type } = req.query;
  const detectedType = type || detectType(value);

  if (!value) {
    return res.status(400).json({
      error: 'Parâmetro "value" é obrigatório',
      errorCode: 'MISSING_VALUE'
    });
  }

  if (!detectedType) {
    return res.status(400).json({
      error: 'Tipo de dado não reconhecido',
      errorCode: 'UNRECOGNIZED_TYPE',
      suggestedTypes: suggestTypes(value)
    });
  }

  let result;
  switch (detectedType) {
    case 'cpf': result = validateCPF(value); break;
    case 'cnpj': result = validateCNPJ(value); break;
    case 'email': result = validateEmail(value); break;
    case 'password': result = validatePassword(value, req.query); break;
    case 'phone-br': result = validatePhoneBR(value); break;
    case 'cep': result = validateCEP(value); break;
    case 'rg': result = validateRG(value); break;
    case 'name': result = validateName(value); break;
    default: 
      return res.status(400).json({
        error: 'Tipo não suportado',
        errorCode: 'UNSUPPORTED_TYPE'
      });
  }

  res.json({
    type: detectedType,
    input: detectedType === 'password' ? '***' : String(value),
    ...result,
    timestamp: new Date().toISOString(),
    requestId: req.id,
    sourceIP: req.ip
  });
});

// Batch processing com melhor tratamento
app.post('/validate/batch', cacheMiddleware, (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  
  if (items.length > 100) {
    return res.status(400).json({
      error: 'Máximo de 100 itens por requisição',
      errorCode: 'BATCH_LIMIT_EXCEEDED'
    });
  }

  const results = items.map((item, index) => {
    if (!item || typeof item !== 'object') {
      return {
        valid: false,
        errors: ['Item inválido'],
        errorCode: 'INVALID_ITEM',
        index
      };
    }

    const { type, value, policy } = item;
    
    if (!type || !value) {
      return {
        valid: false,
        errors: ['Tipo e valor são obrigatórios'],
        errorCode: 'MISSING_FIELDS',
        index
      };
    }

    try {
      switch (type) {
        case 'cpf': return { ...validateCPF(value), index, type };
        case 'cnpj': return { ...validateCNPJ(value), index, type };
        case 'email': return { ...validateEmail(value), index, type };
        case 'password': return { 
          ...validatePassword(value, policy), 
          index, 
          type,
          input: '***'
        };
        case 'phone-br': return { ...validatePhoneBR(value), index, type };
        case 'cep': return { ...validateCEP(value), index, type };
        case 'rg': return { ...validateRG(value), index, type };
        case 'name': return { ...validateName(value), index, type };
        default: 
          return {
            valid: false,
            errors: ['Tipo não suportado'],
            errorCode: 'UNSUPPORTED_TYPE',
            index,
            type
          };
      }
    } catch (error) {
      return {
        valid: false,
        errors: ['Erro na validação'],
        errorCode: 'VALIDATION_ERROR',
        index,
        type
      };
    }
  });

  res.json({
    results,
    summary: {
      total: results.length,
      valid: results.filter(r => r.valid).length,
      invalid: results.filter(r => !r.valid).length
    }
  });
});

// Métricas e monitoring
app.get('/metrics', async (req, res) => {
  const metrics = {
    timestamp: new Date().toISOString(),
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    requests: {
      total: requestCount,
      byType: Object.fromEntries(requestCountByType)
    }
  };
  res.json(metrics);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Erro interno do servidor',
    errorCode: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint não encontrado',
    errorCode: 'NOT_FOUND',
    path: req.originalUrl
  });
});

// Inicialização segura
async function startServer() {
  try {
    if (redisClient) {
      await redisClient.ping();
      console.log('✅ Redis conectado');
    }

    app.listen(config.port, () => {
      console.log(`🚀 valida-br-api rodando em http://localhost:${config.port}`);
      console.log(`📊 Ambiente: ${config.nodeEnv}`);
      console.log(`🔒 Redis: ${redisClient ? 'ativo' : 'inativo'}`);
    });
  } catch (error) {
    console.error('❌ Falha ao iniciar servidor:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Recebido SIGTERM, encerrando graciosamente...');
  if (redisClient) {
    await redisClient.quit();
  }
  process.exit(0);
});

startServer();
