import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

const app = express();

// Configurações
const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development'
};

// Middlewares
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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Muitas requisições, tente novamente mais tarde.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Utils
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

    // Cálculo do primeiro dígito verificador
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      sum += parseInt(digits[i]) * (10 - i);
    }
    
    let remainder = (sum * 10) % 11;
    if (remainder === 10 || remainder === 11) remainder = 0;
    
    if (remainder !== parseInt(digits[9])) {
      throw new ValidationError('Dígito verificador inválido', 'INVALID_CHECK_DIGIT');
    }

    // Cálculo do segundo dígito verificador
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
        region: getCPFRegion(digits)
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
        estado: digits.slice(0, 2)
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

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    
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
    'tempmail.com', 'disposable.com', 'throwaway.com', 'mailinator.com',
    'guerrillamail.com', '10minutemail.com', 'yopmail.com'
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
      forbidCommon = true
    } = policy;

    if (s.length < minLength) errors.push(`Senha deve ter no mínimo ${minLength} caracteres`);
    if (s.length > maxLength) errors.push(`Senha deve ter no máximo ${maxLength} caracteres`);
    if (requireUpper && !/[A-Z]/.test(s)) errors.push('Ao menos 1 letra maiúscula');
    if (requireLower && !/[a-z]/.test(s)) errors.push('Ao menos 1 letra minúscula');
    if (requireNumber && !/\d/.test(s)) errors.push('Ao menos 1 número');
    if (requireSymbol && !/[!@#$%^&*(),.?":{}|<>]/.test(s)) errors.push('Ao menos 1 símbolo');
    
    if (forbidCommon) {
      const commonPasswords = new Set([
        '123456', 'password', '123456789', 'qwerty', 'abc123', 
        '111111', '123123', 'senha', 'admin', 'iloveyou'
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
      normalized: '***',
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
  return Math.min(strength, 5);
}

// Telefone BR
function validatePhoneBR(raw) {
  try {
    const s = onlyDigits(raw);
    const errors = [];
    
    // Remove o código do país se presente
    const local = s.startsWith('55') ? s.slice(2) : s;
    
    if (local.length !== 10 && local.length !== 11) {
      throw new ValidationError('Telefone deve ter 10 (fixo) ou 11 dígitos (celular)', 'INVALID_LENGTH');
    }
    
    const ddd = local.slice(0, 2);
    if (!/^(1[1-9]|2[12478]|3[1-578]|4[1-9]|5[1345]|6[1-9]|7[1-9]|8[1-9]|9[1-9])$/.test(ddd)) {
      throw new ValidationError('DDD inválido', 'INVALID_DDD');
    }
    
    if (local.length === 11 && local[2] !== '9') {
      throw new ValidationError('Celular deve iniciar com 9', 'INVALID_CELL_FORMAT');
    }

    const normalized = `+55 (${ddd}) ${local.slice(2, 7)}-${local.slice(7)}`;
    
    return {
      valid: true,
      normalized,
      metadata: {
        type: local.length === 11 ? 'celular' : 'fixo',
        ddd: ddd
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

// CEP
function validateCEP(raw) {
  try {
    const digits = onlyDigits(raw);
    
    if (digits.length !== 8) {
      throw new ValidationError('CEP deve ter 8 dígitos', 'INVALID_LENGTH');
    }
    
    const normalized = `${digits.slice(0, 5)}-${digits.slice(5)}`;
    
    return {
      valid: true,
      normalized,
      metadata: {
        estado: digits.slice(0, 2),
        regiao: getCEPRegion(digits[0])
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

function getCEPRegion(firstDigit) {
  const regions = {
    '0': 'SP',
    '1': 'SP',
    '2': 'RJ/ES',
    '3': 'MG',
    '4': 'BA/SE',
    '5': 'PE/AL/PB/RN',
    '6': 'CE/PI/MA/PA/AP/AM/RR/AC',
    '7': 'DF/GO/TO/MT/MS/RO',
    '8': 'PR/SC',
    '9': 'RS'
  };
  return regions[firstDigit] || 'Desconhecido';
}

// RG
function validateRG(raw) {
  try {
    const digits = onlyDigits(raw);
    
    if (digits.length < 7 || digits.length > 9) {
      throw new ValidationError('RG deve ter entre 7 e 9 dígitos', 'INVALID_LENGTH');
    }
    
    return {
      valid: true,
      normalized: digits,
      metadata: {
        length: digits.length
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

// Nome
function validateName(raw) {
  try {
    const s = (raw || '').trim();
    
    if (s.length < 2) {
      throw new ValidationError('Nome muito curto', 'TOO_SHORT');
    }
    
    if (s.length > 100) {
      throw new ValidationError('Nome muito longo', 'TOO_LONG');
    }
    
    if (!/^[A-Za-zÀ-ÿ\s'-]+$/.test(s)) {
      throw new ValidationError('Nome contém caracteres inválidos', 'INVALID_CHARACTERS');
    }
    
    return {
      valid: true,
      normalized: s.replace(/\s+/g, ' '),
      metadata: {
        wordCount: s.split(/\s+/).length,
        length: s.length
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

// Detecção de tipo
function detectType(value) {
  if (!value) return null;
  
  const str = value.toString();
  const digits = onlyDigits(str);
  
  // Verifica CPF (11 dígitos e válido)
  if (digits.length === 11) {
    const cpfValidation = validateCPF(str);
    if (cpfValidation.valid) return 'cpf';
  }
  
  // Verifica CNPJ (14 dígitos e válido)
  if (digits.length === 14) {
    const cnpjValidation = validateCNPJ(str);
    if (cnpjValidation.valid) return 'cnpj';
  }
  
  // Verifica CEP (8 dígitos)
  if (digits.length === 8) return 'cep';
  
  // Verifica telefone (10 ou 11 dígitos, começa com DDD válido)
  if (digits.length === 10 || digits.length === 11) {
    const ddd = digits.slice(0, 2);
    if (/^(1[1-9]|2[12478]|3[1-578]|4[1-9]|5[1345]|6[1-9]|7[1-9]|8[1-9]|9[1-9])$/.test(ddd)) {
      return 'phone-br';
    }
  }
  
  // Verifica email (contém @)
  if (str.includes('@')) return 'email';
  
  // Verifica RG (7-9 dígitos)
  if (digits.length >= 7 && digits.length <= 9) return 'rg';
  
  // Verifica nome (2-100 caracteres, apenas letras e espaços)
  if (str.length >= 2 && str.length <= 100 && /^[A-Za-zÀ-ÿ\s'-]+$/.test(str)) {
    return 'name';
  }
  
  return null;
}

// Endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: config.nodeEnv,
    version: '1.0.0'
  });
});

app.get('/validate', (req, res) => {
  try {
    const { value, type } = req.query;
    
    if (!value) {
      return res.status(400).json({
        error: 'Parâmetro "value" é obrigatório',
        errorCode: 'MISSING_VALUE'
      });
    }

    const detectedType = type || detectType(value);
    
    if (!detectedType) {
      return res.status(400).json({
        error: 'Tipo de dado não reconhecido',
        errorCode: 'UNRECOGNIZED_TYPE'
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
      sourceIP: req.ip
    });
  } catch (error) {
    console.error('Error in validate endpoint:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      errorCode: 'INTERNAL_ERROR',
      timestamp: new Date().toISOString()
    });
  }
});

// Batch processing
app.post('/validate/batch', (req, res) => {
  try {
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
            ...validatePassword(value, policy || {}), 
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
  } catch (error) {
    console.error('Error in batch endpoint:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      errorCode: 'INTERNAL_ERROR',
      timestamp: new Date().toISOString()
    });
  }
});

// Test endpoint
app.post('/test', (req, res) => {
  try {
    const values = Array.isArray(req.body) ? req.body : [];
    const out = values.map((value) => {
      const type = detectType(value);
      return {
        input: String(value || ''),
        detectedType: type || 'não reconhecido'
      };
    });
    res.json(out);
  } catch (error) {
    console.error('Error in test endpoint:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      errorCode: 'INTERNAL_ERROR',
      timestamp: new Date().toISOString()
    });
  }
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

// Start server
app.listen(config.port, () => {
  console.log(`🚀 valida-br-api rodando em http://localhost:${config.port}`);
  console.log(`📊 Ambiente: ${config.nodeEnv}`);
});
